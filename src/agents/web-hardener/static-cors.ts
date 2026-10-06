import { skipWs } from "../../core/source/scan.js";
import { analyzeTaint, exprEnd, matchClose } from "../../core/source/index.js";
import type { Finding } from "../../core/types.js";
import { make } from "./fixes.js";
import { bareMatches, lineAt, scopeOf, snippetOf, stringMatches } from "./util.js";
import type { WebFile } from "./util.js";

const ALLOWLISTED = /\ballow\w*|\bALLOW\w*|whitelist|trusted\w*|\.(?:includes|has|indexOf)\s*\(\s*\w*[oO]rigin|\bstartsWith\s*\(|\bendsWith\s*\(/;
const ACAO = /Access-Control-Allow-Origin/gi;
const ACAC_TRUE = /Access-Control-Allow-Credentials["'`]?\s*[,:]\s*(?:value\s*:\s*)?["'`]?true/i;
const CORS_ALLOW_ALL_CALLBACK = /\b(?:cb|callback|done)\s*\(\s*null\s*,\s*true\s*\)/;

type OriginKind = "reflect" | "wildcard" | "safe";

function corsOptionKind(body: string): OriginKind {
  if (/origin\s*:\s*true\b/.test(body)) return "reflect";
  if (/origin\s*:\s*["'`]\*["'`]/.test(body)) return "wildcard";
  if (/origin\s*:\s*(?:req|request)\s*\.\s*headers(?:\s*\.\s*origin|\s*\[\s*["']origin["']\s*\])/.test(body)) return "reflect";
  if (/origin\s*:\s*(?:async\s*)?(?:function\b|\()/.test(body) && CORS_ALLOW_ALL_CALLBACK.test(body) && !ALLOWLISTED.test(body)) return "reflect";
  return "safe";
}

function finding(file: WebFile, target: string, at: number, kind: Exclude<OriginKind, "safe">): Finding {
  const line = lineAt(file, at);
  const reflect = kind === "reflect";
  return make({
    ruleId: "WEB-002",
    title: reflect ? "CORS reflects any origin and allows credentials" : "CORS wildcard origin combined with credentials",
    severity: reflect ? "high" : "low",
    confidence: "high",
    explanation: reflect
      ? "This CORS setup accepts requests from any website (the Origin is echoed back or allowed unconditionally) while also allowing cookies/credentials. A malicious page can then make requests as your logged-in user and read the responses, leaking private data."
      : "This CORS setup sends a wildcard Access-Control-Allow-Origin together with credentials. Browsers refuse that combination, so it does not leak data today, but it signals a misconfiguration and often gets 'fixed' by reflecting the Origin, which is exploitable.",
    evidence: [{ file: file.path, line, snippet: snippetOf(file, at) }],
    fix: {
      summary: "Allow-list exact trusted origins instead of reflecting or wildcarding the Origin.",
      config: "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))",
      agentPrompt: `In ${file.path} at line ${line}, replace the permissive CORS config with an explicit allow-list of my real frontend origins (from an env var). Never combine wildcard or reflected origins with credentials: true.`,
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
    },
    target,
    cwe: "CWE-942",
  });
}

function headerKind(file: WebFile, at: number, valueStart: number): OriginKind {
  const { src } = file;
  const end = exprEnd(src, valueStart, true);
  const value = src.code.slice(valueStart, end).trim();
  if (/^["'`]\*["'`]$/.test(value)) return "wildcard";
  if (value === "" || /^["'`][^"'`$]*["'`]$/.test(value)) return "safe";
  const scope = scopeOf(file, at);
  const body = src.bare.slice(scope.start, scope.end);
  const reflected =
    /(?:req|request)\s*\.\s*headers/.test(value) ||
    /\.get\s*\(\s*["']origin["']\s*\)/i.test(value) ||
    analyzeTaint(src, scope).isTainted(value, at) ||
    /^origin$/i.test(value);
  return reflected && !ALLOWLISTED.test(body) ? "reflect" : "safe";
}

export function corsFindings(file: WebFile, target: string): Finding[] {
  const out: Finding[] = [];
  const { src } = file;
  for (const m of bareMatches(src, /\bcors\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close < 0) continue;
    const body = src.code.slice(open + 1, close - 1);
    const kind = corsOptionKind(body);
    if (kind !== "safe" && /credentials\s*:\s*true/.test(body)) out.push(finding(file, target, m.index, kind));
  }
  if (!ACAC_TRUE.test(src.code)) return out;
  for (const m of stringMatches(src, ACAO)) {
    const tail = /^["'`]?\s*[,:]\s*(?:value\s*:\s*)?/.exec(src.code.slice(m.index + m[0].length));
    if (!tail) continue;
    const valueStart = skipWs(src.code, m.index + m[0].length + tail[0].length);
    const kind = headerKind(file, m.index, valueStart);
    if (kind !== "safe") out.push(finding(file, target, m.index, kind));
  }
  return out;
}
