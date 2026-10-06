import { matchBracket, statementEnd, type PyText } from "./pytext.js";

/** One `def`, found by indentation. Heuristic but robust on formatter-style Python. */
export interface PyFunction {
  readonly name: string;
  /** Offset of the first decorator, or of `def` when there are none. */
  readonly start: number;
  readonly defStart: number;
  readonly paramsStart: number;
  readonly paramsEnd: number;
  readonly bodyStart: number;
  readonly bodyEnd: number;
  readonly params: string;
  /** Decorator source (code view), one entry per decorator. */
  readonly decorators: readonly string[];
}

const DEF = /^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(/gm;

function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

interface DecoSpan {
  readonly start: number;
  readonly end: number;
}

function decoratorSpans(code: string): DecoSpan[] {
  const spans: DecoSpan[] = [];
  for (const m of code.matchAll(/^[ \t]*@/gm)) {
    spans.push({ start: m.index, end: statementEnd(code, m.index) });
  }
  return spans;
}

/** Decorators stacked directly above the def whose line starts at `lineStart`. */
function collectDecorators(
  code: string, spans: readonly DecoSpan[], lineStart: number,
): { start: number; list: string[] } {
  const list: string[] = [];
  let start = lineStart;
  for (;;) {
    const hit = spans.find((s) => s.end <= start && code.slice(s.end, start).trim() === "");
    if (!hit) break;
    list.unshift(code.slice(hit.start, hit.end).trim());
    start = hit.start;
  }
  return { start, list };
}

function findBodyEnd(code: string, from: number, indent: number): number {
  let pos = from;
  while (pos < code.length) {
    const nl = code.indexOf("\n", pos);
    const end = nl === -1 ? code.length : nl;
    const line = code.slice(pos, end);
    if (line.trim() !== "" && indentOf(line) <= indent) return pos;
    if (nl === -1) return code.length;
    pos = nl + 1;
  }
  return code.length;
}

export function findFunctions(pt: PyText): PyFunction[] {
  const code = pt.code;
  const out: PyFunction[] = [];
  const spans = decoratorSpans(code);
  for (const m of code.matchAll(DEF)) {
    const indent = (m[1] ?? "").length;
    const defStart = m.index + indent;
    const paramsStart = m.index + m[0].length - 1;
    const close = matchBracket(code, paramsStart);
    if (close === -1) continue;
    const colon = code.indexOf(":", close);
    const headerEnd = statementEnd(code, close);
    if (colon === -1 || colon > headerEnd + 1) continue;
    const nl = code.indexOf("\n", colon);
    const bodyStart = nl === -1 ? code.length : nl + 1;
    const deco = collectDecorators(code, spans, m.index);
    out.push({
      name: m[2] as string,
      start: deco.start,
      defStart,
      paramsStart,
      paramsEnd: close,
      bodyStart,
      bodyEnd: findBodyEnd(code, bodyStart, indent),
      params: code.slice(paramsStart + 1, close - 1),
      decorators: deco.list,
    });
  }
  return out;
}

/** Innermost function whose body contains the offset. */
export function enclosing(funcs: readonly PyFunction[], offset: number): PyFunction | undefined {
  let best: PyFunction | undefined;
  for (const f of funcs) {
    if (offset >= f.bodyStart && offset < f.bodyEnd && (!best || f.bodyStart >= best.bodyStart)) best = f;
  }
  return best;
}

/** Direct request-data accessors across Flask, Django, FastAPI/Starlette. */
export const REQUEST_SOURCE =
  /\brequest\s*\.\s*(?:args|form|json|values|data|files|cookies|headers|get_json|get_data|stream|GET|POST|FILES|body|query_params|path_params|META|view_args)\b|\brequest\.get_json\s*\(|\bawait\s+request\.(?:json|form|body)\s*\(/;

const NON_USER_PARAMS = new Set([
  "self", "cls", "request", "response", "db", "session", "conn", "cursor", "background_tasks", "background",
  "current_user", "user", "settings", "args", "kwargs", "req", "res", "websocket",
]);
const ASSIGN = /^[ \t]*(\w+)[ \t]*(?::[^=\n]+)?=(?!=)/gm;
/** Calls that turn user input into a safe value for path/SQL purposes. */
const SANITIZER = /\b(?:secure_filename|basename|safe_join|int|float|bool|UUID|uuid4|quote_plus)\s*\(/;
const WORD = /[A-Za-z_]\w*/g;

function paramNames(params: string): string[] {
  const names: string[] = [];
  let depth = 0;
  let current = "";
  const parts: string[] = [];
  for (const c of params) {
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    if (c === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else current += c;
  }
  parts.push(current);
  for (const part of parts) {
    const m = /^\s*\**(\w+)/.exec(part);
    if (!m) continue;
    // Dependency-injected params are not attacker-controlled data.
    if (/=\s*(?:Depends|Security)\s*\(/.test(part) || /Annotated\[[^\]]*Depends/.test(part)) continue;
    if (!NON_USER_PARAMS.has(m[1] as string)) names.push(m[1] as string);
  }
  return names;
}

export function usesRequestData(text: string, tainted: ReadonlySet<string>): boolean {
  if (REQUEST_SOURCE.test(text)) return true;
  for (const w of text.matchAll(WORD)) if (tainted.has(w[0])) return true;
  return false;
}

/**
 * Names that carry user input inside `fn`: route-function parameters (path/query/body params) and
 * locals assigned from request accessors or from other tainted names (to a fixed point, 4 rounds).
 * Module-level code has no tainted names.
 */
export function taintedNames(pt: PyText, fn: PyFunction | undefined): Set<string> {
  const tainted = new Set<string>();
  if (!fn) return tainted;
  const isRoute = fn.decorators.some((d) => ROUTE_DECORATOR.test(d)) || /\brequest\b/.test(fn.params);
  if (isRoute) for (const n of paramNames(fn.params)) tainted.add(n);
  const body = pt.code.slice(fn.bodyStart, fn.bodyEnd);
  const assigns: { name: string; expr: string }[] = [];
  for (const m of body.matchAll(ASSIGN)) {
    const exprStart = fn.bodyStart + m.index + m[0].length;
    assigns.push({ name: m[1] as string, expr: pt.code.slice(exprStart, statementEnd(pt.code, exprStart)) });
  }
  const sanitized = new Set<string>();
  for (const a of assigns) if (SANITIZER.test(a.expr)) sanitized.add(a.name);
  for (let round = 0; round < 4; round++) {
    let changed = false;
    for (const a of assigns) {
      if (!tainted.has(a.name) && usesRequestData(a.expr, tainted)) {
        tainted.add(a.name);
        changed = true;
      }
    }
    if (!changed) break;
  }
  for (const n of sanitized) tainted.delete(n);
  return tainted;
}

export const ROUTE_DECORATOR =
  /^@\s*\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|head|options|api_route|websocket)\s*\(|^@\s*(?:api_view|action)\b/;

/** Last assignment of `name` before `before` within the enclosing function (or module). Returns the RHS range. */
export function findAssignment(
  pt: PyText, fn: PyFunction | undefined, name: string, before: number,
): { start: number; end: number } | undefined {
  const from = fn ? fn.bodyStart : 0;
  const re = new RegExp(`^[ \\t]*${name}[ \\t]*(?::[^=\\n]+)?=(?!=)`, "gm");
  const region = pt.code.slice(from, before);
  let found: { start: number; end: number } | undefined;
  for (const m of region.matchAll(re)) {
    const start = from + m.index + m[0].length;
    found = { start, end: statementEnd(pt.code, start) };
  }
  return found;
}
