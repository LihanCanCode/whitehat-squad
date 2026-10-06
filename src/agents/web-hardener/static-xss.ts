import { skipWs } from "../../core/source/scan.js";
import { analyzeTaint, exprEnd, findUnits, matchClose, parseParams } from "../../core/source/index.js";
import { skipTemplate } from "../../core/source/scan.js";
import type { Finding } from "../../core/types.js";
import { make } from "./fixes.js";
import { bareMatches, lineAt, scopeOf, snippetOf } from "./util.js";
import type { WebFile } from "./util.js";

interface Sink {
  readonly name: string;
  readonly re: RegExp;
  /** Where the value expression starts, relative to the match end. */
  readonly kind: "expr" | "call";
}

const SINKS: readonly Sink[] = [
  { name: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*/g, kind: "expr" },
  { name: "innerHTML/outerHTML", re: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*/g, kind: "expr" },
  { name: "document.write", re: /\bdocument\.write(?:ln)?\s*\(\s*/g, kind: "call" },
];

const SAFE_CALL =
  /^(?:(?:React\.)?useMemo\(\s*\(\)\s*=>\s*)?(?:(?:DOMPurify|purify|dompurify|sanitizer)\s*\.\s*\w+|[\w$.]*sanitize\w*|xss|filterXSS|escapeHtml\w*|escapeHTML|escape|he\s*\.\s*(?:escape|encode)|renderToString|renderToStaticMarkup)\s*\(/i;
const UPPER = /^[A-Z][A-Z0-9_]*$/;
const NUMERICISH = /^(?:\d+|(?:Number|parseInt|parseFloat|Math\.\w+)\(.*\)|.*\.length|.*\.toFixed\(\d*\))$/s;
const INSIDE_STYLE_TAG = /<style\b[^>]*$/i;
const INSIDE_SCRIPT_TAG = /<script\b[^>]*$/i;
const JSON_ESCAPE = /\\u003c|u003c|\.replace\s*\(\s*\/<\/g|serialize\w*|safeJson\w*|escapeJson\w*|htmlEscape\w*/i;
const MAX_DEPTH = 3;
/** Re-serializing an element's own rendered markup (el.innerHTML) is not a new injection. */
const DOM_READ = /^[\w$.[\]?]+\.(?:innerHTML|outerHTML|textContent|innerText)$/;

/** Top-level `+` split of the bare text [from, to), as offsets. */
function splitPlus(file: WebFile, from: number, to: number): Array<[number, number]> {
  const b = file.src.bare;
  const parts: Array<[number, number]> = [];
  let start = from;
  let depth = 0;
  for (let i = from; i < to; i++) {
    const c = b.charAt(i);
    if (c === "`") {
      i = skipTemplate(file.src, i) - 1;
    } else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "+" && depth === 0) {
      parts.push([start, i]);
      start = i + 1;
    }
  }
  parts.push([start, to]);
  return parts.map(([a, z]) => [skipWs(b, a), z] as [number, number]);
}

function callEndsAt(file: WebFile, from: number, to: number): boolean {
  const open = file.src.bare.indexOf("(", from);
  if (open < 0 || open >= to) return false;
  const close = matchClose(file.src, open);
  return close > 0 && /^\s*(?:[,;)}\]]|$)/.test(file.src.code.slice(close, to + 1));
}

function templateSafe(file: WebFile, from: number, to: number): boolean {
  const { src } = file;
  if (skipTemplate(src, from) !== to) return false;
  for (let i = from + 1; i < to - 1; i++) {
    if (src.bare.charAt(i) !== "$" || src.bare.charAt(i + 1) !== "{") continue;
    const close = matchClose(src, i + 1);
    if (close < 0) return false;
    const expr = src.code.slice(i + 2, close - 1).trim();
    if (!(UPPER.test(expr) || NUMERICISH.test(expr) || (SAFE_CALL.test(expr) && callEndsAt(file, i + 2, close - 1)))) return false;
    i = close - 1;
  }
  return true;
}

interface Ctx2 {
  readonly file: WebFile;
  readonly sinkAt: number;
}

/** Writes to `name` that happen before the sink in the same function (or at module level). */
function writesOf(file: WebFile, name: string, sinkAt: number): Array<{ from: number; compound: boolean }> {
  const { src } = file;
  const scope = scopeOf(file, sinkAt);
  const units = findUnits(src);
  const re = new RegExp(String.raw`(?<![\w$.])${name.replace(/\$/g, String.raw`\$`)}\s*(\+|\|\||\?\?)?=(?![=>])`, "g");
  const out: Array<{ from: number; compound: boolean }> = [];
  for (const m of src.bare.matchAll(re)) {
    if (m.index >= sinkAt) break;
    const inScope = m.index >= scope.start && m.index < scope.end;
    const atModule = !units.some((u) => m.index >= u.start && m.index < u.end);
    if (inScope || atModule) out.push({ from: skipWs(src.bare, m.index + m[0].length), compound: Boolean(m[1]) });
  }
  return out;
}

/** The value uses a parameter of the enclosing function (component props, handler args): caller-controlled. */
function fromParams(file: WebFile, text: string, at: number): boolean {
  const names = parseParams(scopeOf(file, at).params).flatMap((p) => p.names);
  return names.some((n) => new RegExp(`(?<![\\w$.])${n.replace(/\$/g, "\\$")}(?![\\w$])`).test(text));
}

function userTainted(file: WebFile, text: string, at: number): boolean {
  const scope = scopeOf(file, at);
  const names = parseParams(scope.params).flatMap((p) => p.names).filter((n) => /^(?:searchParams|params|query|req|request)$/.test(n));
  const taint = analyzeTaint(file.src, scope, {
    taintedNames: names,
    extraSources: [/(?:window\.)?location\s*\.\s*(?:hash|search|href)\b/, /document\s*\.\s*(?:cookie|referrer|URL)\b/, /\bwindow\.name\b/],
  });
  return taint.isTainted(text, at);
}

function isSafeRange(ctx: Ctx2, from: number, to: number, depth: number): boolean {
  const { file } = ctx;
  const { src } = file;
  const code = src.code.slice(from, to).trim();
  if (code === "") return true;
  const bare = src.bare.slice(from, to).trim();
  if (/^(["'])\s*\1$/.test(bare)) return true;
  if (bare.startsWith("`") && templateSafe(file, skipWs(src.bare, from), from + src.bare.slice(from, to).trimEnd().length)) return true;
  const parts = splitPlus(file, from, to);
  if (parts.length > 1) return parts.every(([a, z]) => isSafeRange(ctx, a, z, depth));
  if (SAFE_CALL.test(code) && callEndsAt(file, from, to)) return true;
  if (DOM_READ.test(code)) return true;
  if (/^JSON\s*\.\s*stringify\s*\(/.test(code)) {
    const prev = src.code.slice(Math.max(0, ctx.sinkAt - 300), ctx.sinkAt);
    const inScript = INSIDE_SCRIPT_TAG.test(prev);
    return !userTainted(file, code, ctx.sinkAt) || !inScript || JSON_ESCAPE.test(code);
  }
  if (!/^[A-Za-z_$][\w$]*$/.test(code) || depth >= MAX_DEPTH) return false;
  const writes = writesOf(file, code, ctx.sinkAt);
  // No local definition (e.g. an imported THEME_INIT_SCRIPT): an UPPER_SNAKE_CASE name is a constant by convention.
  if (writes.length === 0) return UPPER.test(code);
  return writes.every((w) => isSafeRange(ctx, w.from, exprEnd(src, w.from, true), depth + 1));
}

function explanationFor(name: string, scriptJson: boolean): string {
  if (scriptJson) {
    return (
      "User-influenced data is turned into JSON and written inside an inline <script> with " +
      `${name}. JSON.stringify does not escape "</script>", so a value such as "</script><script>alert(1)</script>" ends the script early and runs attacker script (XSS). Escape "<" as \\u003c in the JSON.`
    );
  }
  return (
    `A non-constant value is written into the page with ${name} and it is not wrapped in an HTML sanitizer at that point. ` +
    "If any part of that value comes from users, URLs or an API, an attacker can inject script (XSS) and take over sessions."
  );
}

function build(file: WebFile, target: string, name: string, at: number, scriptJson: boolean, traced = true): Finding {
  const line = lineAt(file, at);
  return make({
    ruleId: "WEB-003",
    title: scriptJson ? "User data serialized into an inline script without escaping" : `Unsanitized value written with ${name}`,
    severity: "high",
    // Calibrated on public repos: values not traced to users/URLs/requests are usually app-owned HTML.
    confidence: traced ? "medium" : "low",
    explanation: explanationFor(name, scriptJson) + (traced ? "" : " whsquad could not trace this value to user input; check where it comes from."),
    evidence: [{ file: file.path, line, snippet: snippetOf(file, at) }],
    fix: {
      summary: scriptJson ? "Escape '<' in the serialized JSON (or use a serializer that does)." : "Render as text, or wrap the exact value in DOMPurify.sanitize() before inserting HTML.",
      config: scriptJson
        ? "const safe = JSON.stringify(data).replace(/</g, '\\\\u003c');\n<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: safe }} />"
        : "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
      agentPrompt: `In ${file.path} near line ${line}, ${scriptJson ? "escape '<' as \\u003c in the JSON written into this inline <script>" : `stop inserting raw HTML via ${name}; prefer rendering text, and if HTML is required wrap the value that reaches the sink with DOMPurify.sanitize()`}. A sanitizer elsewhere in the file does not protect this sink.`,
      references: ["https://owasp.org/www-community/attacks/xss/", "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations"],
    },
    target,
    cwe: "CWE-79",
  });
}

export function xssFindings(file: WebFile, target: string): Finding[] {
  const out: Finding[] = [];
  const { src } = file;
  for (const sink of SINKS) {
    for (const m of bareMatches(src, sink.re)) {
      const from = m.index + m[0].length;
      const to = exprEnd(src, from, true);
      if (sink.name === "dangerouslySetInnerHTML" && INSIDE_STYLE_TAG.test(src.code.slice(Math.max(0, m.index - 200), m.index))) continue;
      if (isSafeRange({ file, sinkAt: m.index }, from, to, 0)) continue;
      const code = src.code.slice(from, to).trim();
      const scriptJson = /^JSON\s*\.\s*stringify\s*\(/.test(code);
      const traced = scriptJson || userTainted(file, code, m.index) || fromParams(file, code, m.index);
      out.push(build(file, target, scriptJson ? "dangerouslySetInnerHTML in a <script>" : sink.name, m.index, scriptJson, traced));
    }
  }
  if (file.isMarkup) {
    for (const m of file.markup.matchAll(/\bv-html\s*=\s*(["'])([\s\S]*?)\1/g)) {
      const expr = (m[2] ?? "").trim();
      if (expr === "" || /^(["'`])[^"'`$]*\1$/.test(expr) || SAFE_CALL.test(expr)) continue;
      out.push(build(file, target, "v-html", m.index, false));
    }
  }
  return out;
}
