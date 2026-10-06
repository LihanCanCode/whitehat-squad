import { findUnits, matchClose, parseParams, splitArgs } from "../../core/source/index.js";
import { readFunctionAt } from "../../core/source/functions.js";
import type { Finding } from "../../core/types.js";
import { make } from "./fixes.js";
import { lastRhs } from "./static-fs.js";
import { bareMatches, codeMatches, lineAt, snippetOf } from "./util.js";
import type { WebFile } from "./util.js";

const SENSITIVE = /\b\w*(?:token|session|auth|jwt|secret|password|credential|bearer|apikey)\w*\b/i;
const ORIGIN_CHECK_CALL = /(?:allow|trust|valid|check|verify|origin)\w*\s*\(/i;
const COMPARE_NEAR = /[!=]==?|\.(?:includes|has|indexOf|startsWith|endsWith|test)\s*\(/;

interface Handler {
  readonly params: string;
  readonly start: number;
  readonly end: number;
}

function handlerOf(file: WebFile, argStart: number, argEnd: number): Handler | undefined {
  const { src } = file;
  const init = readFunctionAt(src, argStart);
  if (init) return { params: init.params, start: init.bodyStart, end: init.end };
  const name = src.bare.slice(argStart, argEnd).trim();
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  const unit = findUnits(src).find((u) => u.name === name);
  return unit ? { params: unit.params, start: unit.bodyStart, end: unit.end } : undefined;
}

/** Does the handler body compare / check the message origin (or source)? */
function checksOrigin(file: WebFile, h: Handler, event: string, destructured: readonly string[]): boolean {
  const body = file.src.bare.slice(h.start, h.end);
  const names = [event ? `${event}\\s*\\.\\s*origin` : "", event ? `${event}\\s*\\.\\s*source` : "", ...(destructured.includes("origin") ? ["(?<![\\w$.])origin"] : []), ...(destructured.includes("source") ? ["(?<![\\w$.])source"] : [])].filter(Boolean);
  for (const n of names) {
    for (const m of body.matchAll(new RegExp(`${n}\\b`, "g"))) {
      const around = body.slice(Math.max(0, m.index - 45), m.index + m[0].length + 45);
      if (COMPARE_NEAR.test(around) || ORIGIN_CHECK_CALL.test(body.slice(Math.max(0, m.index - 40), m.index))) return true;
    }
  }
  return false;
}

function usesData(file: WebFile, h: Handler, event: string, destructured: readonly string[]): boolean {
  const body = file.src.bare.slice(h.start, h.end);
  return (event !== "" && new RegExp(`\\b${event}\\s*\\.\\s*data\\b`).test(body)) || (destructured.includes("data") && /(?<![\w$.])data\b/.test(body));
}

export function messageListenerFindings(file: WebFile, target: string): Finding[] {
  const out: Finding[] = [];
  const { src } = file;
  for (const m of codeMatches(src, /\baddEventListener\s*\(\s*["']message["']\s*,/g)) {
    const open = m.index + m[0].indexOf("(");
    const close = matchClose(src, open);
    if (close < 0) continue;
    const arg = splitArgs(src, open + 1, close - 1)[1];
    const handler = arg ? handlerOf(file, arg.start, arg.end) : undefined;
    if (!handler) continue;
    const p = parseParams(handler.params)[0];
    const event = p && !p.destructured ? (p.names[0] ?? "") : "";
    const destructured = p?.destructured ? p.names : [];
    if (!usesData(file, handler, event, destructured) || checksOrigin(file, handler, event, destructured)) continue;
    const line = lineAt(file, m.index);
    out.push(
      make({
        ruleId: "WEB-009",
        title: "Message listener does not check the sender's origin",
        severity: "medium",
        confidence: "medium",
        explanation:
          "This window.addEventListener('message') handler uses event.data without comparing event.origin to your own origin or an allowlist. " +
          "Any page that can open or embed your site (a popup, an iframe, another tab) can post a crafted message and drive whatever the handler does with it: change state, navigate, or inject HTML.",
        evidence: [{ file: file.path, line, snippet: snippetOf(file, m.index) }],
        fix: {
          summary: "Compare event.origin to an exact allowlist before reading event.data.",
          config: "const ALLOWED = new Set(['https://app.example.com']);\nwindow.addEventListener('message', (event) => {\n  if (!ALLOWED.has(event.origin)) return;\n  handle(event.data);\n});",
          agentPrompt: `In ${file.path} at line ${line}, add an origin check at the top of this 'message' handler: return unless event.origin is exactly my own origin or an entry in an explicit allowlist. Validate the shape of event.data too.`,
          references: ["https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns", "https://cwe.mitre.org/data/definitions/346.html"],
        },
        target,
        cwe: "CWE-346",
      }),
    );
  }
  return out;
}

export function postMessageFindings(file: WebFile, target: string): Finding[] {
  const out: Finding[] = [];
  const { src } = file;
  for (const m of bareMatches(src, /\.\s*postMessage\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close < 0) continue;
    const args = splitArgs(src, open + 1, close - 1);
    const second = args[1];
    const first = args[0];
    if (!first || !second || !/^["'`]\*["'`]$/.test(src.code.slice(second.start, second.end).trim())) continue;
    const bare = src.bare.slice(first.start, first.end);
    let sensitive = SENSITIVE.test(bare);
    const ident = /^[A-Za-z_$][\w$]*$/.exec(bare.trim());
    if (!sensitive && ident) sensitive = SENSITIVE.test(lastRhs(file, ident[0], m.index) ?? "") || SENSITIVE.test(ident[0]);
    if (!sensitive) continue;
    const line = lineAt(file, m.index);
    out.push(
      make({
        ruleId: "WEB-010",
        title: "Token or session data sent with postMessage to any origin",
        severity: "high",
        confidence: "high",
        explanation:
          "postMessage is called with targetOrigin '*' and a payload that carries a token, session or auth value. The browser delivers it to whatever page currently occupies the target window, " +
          "so a malicious site that navigated or framed that window receives the credential.",
        evidence: [{ file: file.path, line, snippet: snippetOf(file, m.index) }],
        fix: {
          summary: "Pass the exact receiving origin instead of '*'.",
          config: "target.postMessage({ type: 'auth', token }, 'https://app.example.com');",
          agentPrompt: `In ${file.path} at line ${line}, replace the '*' targetOrigin in this postMessage call with the exact origin of the receiving window (from config), so the token is only delivered to it.`,
          references: ["https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns", "https://cwe.mitre.org/data/definitions/201.html"],
        },
        target,
        cwe: "CWE-201",
      }),
    );
  }
  return out;
}
