import { parseBindingNames, parseParams } from "./bindings.js";
import { readFunctionAt } from "./functions.js";
import { createSource } from "./lexer.js";
import type { Source } from "./lexer.js";
import { exprEnd, matchClose, skipWs, typeAnnotationEquals } from "./scan.js";
import { findUnits } from "./units.js";
import type { FunctionUnit } from "./units.js";

/**
 * Per-unit, ordered, scoped taint analysis (no dependency on a parser).
 *
 * Model: every `const/let/var` declaration, assignment, member write, `for..of/in` header and array
 * callback parameter is a "site". Sites are processed in source order; each one records an event for the
 * names it binds ("tainted"/"clean" from `effect` offset until its scope ends). A name is tainted at an
 * offset when its latest applicable event is tainted. Only sites inside the unit plus module-level sites
 * (outside every unit) are considered, so taint never leaks between handlers.
 */

export interface SourcePattern {
  readonly id: string;
  readonly label: string;
  readonly re: RegExp;
}

const L = String.raw`(?<![\w$])(?<!(?<!\.)\.)`;
const rx = (s: string): RegExp => new RegExp(s);

/** Catalog of request-controlled expressions. Tested against string/comment-free code. */
export const REQUEST_SOURCES: readonly SourcePattern[] = [
  { id: "req-props", label: "request properties", re: rx(`${L}(?:req|request)\\s*\\.\\s*(?:body|query|params|headers|cookies|nextUrl|url|originalUrl|files?|rawBody)\\b`) },
  { id: "req-readers", label: "request body readers", re: rx(`${L}(?:req|request)\\s*\\.\\s*(?:json|formData|text|arrayBuffer|blob)\\s*\\(`) },
  { id: "search-params", label: "URL search params", re: /(?<![\w$])searchParams\b/ },
  { id: "form-data", label: "FormData", re: rx(`${L}formData\\s*\\.\\s*(?:get|getAll|entries)\\s*\\(`) },
  { id: "hono-req", label: "Hono request", re: rx(`${L}c\\s*\\.\\s*req\\s*\\.\\s*(?:json|parseBody|formData|text|query|queries|param|header|arrayBuffer|blob)\\s*\\(`) },
  { id: "koa-ctx", label: "Koa request", re: rx(`${L}ctx\\s*\\.\\s*(?:request\\s*\\.\\s*)?(?:body|query|params|headers|querystring|url|originalUrl)\\b`) },
  { id: "next-headers", label: "request headers/cookies", re: rx(`${L}(?:headers|cookies)\\s*\\(\\s*\\)`) },
  { id: "h3", label: "h3/Nuxt request helpers", re: rx(`${L}(?:getQuery|getRouterParams?|readBody|readFormData|readMultipartFormData|getCookie|getHeaders?)\\s*\\(`) },
  { id: "lambda-event", label: "Lambda event", re: rx(`${L}event\\s*\\.\\s*(?:body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers)\\b`) },
];

/** Call heads (callee text without spaces, ending in "(") whose result is NOT tainted. */
export const DEFAULT_SANITIZERS: readonly RegExp[] = [
  /^(?:Number|parseInt|parseFloat|BigInt|Boolean|encodeURIComponent|encodeURI|escape)\($/,
  /^Number\.(?:parseInt|parseFloat|isInteger)\($/,
  /^(?:path\.)?basename\($/,
  /^(?:DOMPurify\.sanitize|validator\.escape|sanitize\w*|escape\w+|escapeHtml)\($/,
];

export interface TaintSpec {
  /** Extra request-like expressions (a regex, or a literal expression like "window.location.hash"). */
  readonly extraSources?: ReadonlyArray<RegExp | string>;
  /** Additional sanitizer call heads, matched against e.g. "clean(" or "validator.toInt(". */
  readonly extraSanitizers?: readonly RegExp[];
  /** Replaces the default sanitizer list (extraSanitizers still apply). */
  readonly sanitizers?: readonly RegExp[];
  /** Names tainted from the start of the unit. */
  readonly taintedNames?: readonly string[];
  /** Seed handler / server action parameters (default true). */
  readonly seedParams?: boolean;
}

export interface TaintAnalysis {
  /**
   * Does `exprText` (code text of an expression, e.g. a sink argument) depend on request data?
   * `atOffset` selects the state at that source offset (use it for ordered precision); without it the
   * state at the end of the unit is used.
   */
  isTainted(exprText: string, atOffset?: number): boolean;
  /** Names tainted at `atOffset` (default: end of the unit; loop/callback variables included). */
  taintedNames(atOffset?: number): Set<string>;
  /** Where a tainted name's data comes from, e.g. "req.body"; undefined when clean/unknown. */
  originOf(name: string, atOffset?: number): string | undefined;
}

// ---------------------------------------------------------------------------------------------
// Expression evaluation

const PASSTHROUGH_HEAD =
  /^(?:String|Object\.(?:assign|fromEntries|entries|values|keys|freeze|create)|Array\.(?:from|of)|JSON\.(?:parse|stringify)|decodeURIComponent|decodeURI|atob|btoa|Buffer\.from|structuredClone|path(?:\.posix|\.win32)?\.(?:join|resolve|normalize|relative)|URL|URLSearchParams|Request|Headers|FormData|util\.format|sprintf|Promise\.(?:all|resolve|allSettled)|Array|Set|Map)\($/;
const PASSTHROUGH_METHOD = /(?:^|\.)(?:concat|join|replace|replaceAll|padStart|padEnd|format|resolve|normalize|toString)\($/;
/** `/\D/g, ""` or `/[^<safe class>]/g, ""`: the replacement deletes everything except digits/letters/_/-. */
const ALLOWLIST_STRIP = /^\s*\/(?:\\D|\[\^(?:\\d|\\w|0-9|a-z|A-Z|_|-)+\])\+?\/[gimsuy]*\s*,\s*(["'`])\1\s*$/;
const PARSE_METHODS = new Set(["parse", "safeParse", "parseAsync", "safeParseAsync", "validateSync", "validate"]);
/** Receivers whose .parse()/.validate() is not schema validation. */
export const NOT_SCHEMA_ROOTS = /^(?:\(?\s*)?(?:JSON|Date|Number|Math|Intl|URL|url|path|qs|querystring|YAML|yaml|csv|Papa|marked|Temporal)\b/;
const CALL = /((?:new\s+)?[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)*)\s*(?:<[^()]*?>)?\s*\(/g;
const IDENT = /(?<![\w$])(?<!(?<!\.)\.)[A-Za-z_$][\w$]*/g;

function matchParenText(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return i + 1;
  }
  return -1;
}

function matchOpenText(text: string, closeIdx: number): number {
  const close = text.charAt(closeIdx);
  const open = close === ")" ? "(" : close === "]" ? "[" : "{";
  let depth = 0;
  for (let i = closeIdx; i >= 0; i--) {
    const c = text.charAt(i);
    if (c === close) depth++;
    else if (c === open && --depth === 0) return i;
  }
  return -1;
}

/** Start of the receiver expression that ends just before the `.` at `dot`. */
function receiverStart(text: string, dot: number): number {
  let j = dot;
  for (let guard = 0; guard < 60; guard++) {
    while (j > 0 && /\s/.test(text.charAt(j - 1))) j--;
    const c = text.charAt(j - 1);
    if (c === ")" || c === "]" || c === "}") {
      const o = matchOpenText(text, j - 1);
      if (o < 0) return -1;
      j = o;
      continue;
    }
    if (/[\w$]/.test(c)) {
      while (j > 0 && /[\w$]/.test(text.charAt(j - 1))) j--;
      let k = j;
      while (k > 0 && /\s/.test(text.charAt(k - 1))) k--;
      if (text.charAt(k - 1) === ".") {
        j = k - 1;
        continue;
      }
    }
    break;
  }
  return j;
}

function blankSpans(text: string, spans: ReadonlyArray<readonly [number, number]>): string {
  if (spans.length === 0) return text;
  const chars = text.split("");
  for (const [from, to] of spans) for (let i = Math.max(0, from); i < Math.min(to, chars.length); i++) chars[i] = " ";
  return chars.join("");
}

/** Removes sanitized calls and the arguments of calls whose result does not carry argument taint. */
/** `code` is the same span with string/regex contents kept (same offsets), used only to read regex literals. */
function neutralize(text: string, sanitizers: readonly RegExp[], code: string = text): string {
  const spans: Array<[number, number]> = [];
  const re = new RegExp(CALL.source, "g");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const open = m.index + m[0].length - 1;
    const close = matchParenText(text, open);
    if (close < 0) continue;
    const head = `${(m[1] ?? "").replace(/^new\s+/, "").replace(/\s+/g, "")}(`;
    const last = head.slice(0, -1).split(/\?\.|\./).pop() ?? "";
    let before = m.index;
    while (before > 0 && /\s/.test(text.charAt(before - 1))) before--;
    const chained = text.charAt(before - 1) === "." && !head.includes(".");
    if (chained && PARSE_METHODS.has(last)) {
      const start = receiverStart(text, before - 1);
      if (start >= 0 && !NOT_SCHEMA_ROOTS.test(text.slice(start, before - 1).trim())) {
        spans.push([start, close]);
        re.lastIndex = close;
        continue;
      }
    }
    if (!chained && head.includes(".") && PARSE_METHODS.has(last) && !NOT_SCHEMA_ROOTS.test(head)) {
      spans.push([m.index, close]);
      re.lastIndex = close;
      continue;
    }
    if (sanitizers.some((s) => s.test(head))) {
      spans.push([m.index, close]);
      re.lastIndex = close;
      continue;
    }
    // x.replace(/\D/g, "") / .replace(/[^a-z0-9_-]/gi, ""): everything outside a safe class is deleted,
    // so no quote, comma, slash or operator can survive (public-repo study: phone-number filters).
    if ((chained || head.includes(".")) && (last === "replace" || last === "replaceAll") && ALLOWLIST_STRIP.test(code.slice(open + 1, close - 1))) {
      // `x.replace(...)` has the receiver in its head; `f(x).replace(...)` needs the receiver found.
      const start = chained ? receiverStart(text, before - 1) : m.index;
      if (start >= 0) {
        spans.push([start, close]);
        re.lastIndex = close;
        continue;
      }
    }
    if (PASSTHROUGH_HEAD.test(head) || PASSTHROUGH_METHOD.test(head)) continue;
    spans.push([open + 1, close - 1]);
    re.lastIndex = close;
  }
  return blankSpans(text, spans);
}

function isObjectKey(text: string, start: number, end: number): boolean {
  if (!/^\s*:(?!:)/.test(text.slice(end, end + 8))) return false;
  let k = start;
  while (k > 0 && /\s/.test(text.charAt(k - 1))) k--;
  const p = text.charAt(k - 1);
  return p === "{" || p === ",";
}

// ---------------------------------------------------------------------------------------------
// Sites

interface Site {
  kind: "decl" | "assign" | "member" | "for" | "cb";
  names: string[];
  start: number;
  rhsStart: number;
  rhsEnd: number;
  effect: number;
  /** Scope end (exclusive) for block-scoped declarations, loop and callback variables. */
  until?: number;
  loopVar?: boolean;
  compound?: boolean;
  noInit?: boolean;
  depth: number;
}

const DECL = /(?<![\w$.])(const|let|var)\s+/g;
const ASSIGN =
  /(?<![\w$.])([A-Za-z_$][\w$]*)((?:\s*\?\.\s*[A-Za-z_$][\w$]*|\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]{0,80}\])*)\s*(\+|\|\||&&|\?\?)?=(?![=>])/g;
// Prefix whitespace is [ \t] (the newline itself is a prefix char) and bodies are bounded: with `\s*`
// on both sides of `\(?`, a file of blank lines was cubic (security review: hostile-input.test.ts).
const DESTRUCT_ASSIGN = /(?:^|[;{}\n(])[ \t]*\(?[ \t]*(\{[^{}]{0,2000}\}|\[[^[\]]{0,2000}\])\s*=(?![=>])/g;
const CALLBACK =
  /([A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)*)\s*\.\s*(?:map|forEach|filter|find|findLast|some|every|flatMap|reduce|reduceRight|then)\s*\(\s*(?=(?:async\s+)?(?:\(|[A-Za-z_$]))/g;
const ID_AT = /[A-Za-z_$][\w$]*/y;
const OF_IN = /(?:of|in)\b/y;

function scanDeclarators(src: Source, pos: number, startOfStmt: number, out: Site[], spans: Array<[number, number]>): void {
  const b = src.bare;
  let i = pos;
  let first = true;
  for (let guard = 0; guard < 200; guard++) {
    i = skipWs(b, i);
    const targetStart = i;
    let names: string[];
    let targetEnd: number;
    const c = b.charAt(i);
    if (c === "{" || c === "[") {
      const close = matchClose(src, i);
      if (close < 0) return;
      names = parseBindingNames(b.slice(i, close));
      targetEnd = close;
    } else {
      ID_AT.lastIndex = i;
      const id = ID_AT.exec(b);
      if (!id) return;
      names = [id[0]];
      targetEnd = i + id[0].length;
    }
    let j = skipWs(b, targetEnd);
    if (b.charAt(j) === "!") j = skipWs(b, j + 1);
    if (b.charAt(j) === ":") {
      const eq = typeAnnotationEquals(src, j);
      if (eq < 0) {
        out.push({ kind: "decl", names, start: first ? startOfStmt : targetStart, rhsStart: j, rhsEnd: j, effect: j, noInit: true, depth: 0 });
        return;
      }
      j = eq;
    }
    const start = first ? startOfStmt : targetStart;
    first = false;
    if (b.charAt(j) === "=" && b.charAt(j + 1) !== "=" && b.charAt(j + 1) !== ">") {
      const rhsStart = skipWs(b, j + 1);
      const rhsEnd = exprEnd(src, rhsStart, true);
      spans.push([targetStart, j + 1]);
      out.push({ kind: "decl", names, start, rhsStart, rhsEnd, effect: rhsEnd, depth: 0 });
      i = rhsEnd;
      if (b.charAt(i) === ",") {
        i++;
        continue;
      }
      return;
    }
    OF_IN.lastIndex = j;
    const w = OF_IN.exec(b);
    if (w) {
      const rhsStart = skipWs(b, j + w[0].length);
      const rhsEnd = exprEnd(src, rhsStart, false);
      const k = skipWs(b, b.charAt(rhsEnd) === ")" ? rhsEnd + 1 : rhsEnd);
      const until = b.charAt(k) === "{" ? matchClose(src, k) : exprEnd(src, k, false);
      out.push({ kind: "for", names, start, rhsStart, rhsEnd, effect: rhsEnd + 1, until: until < 0 ? undefined : until, loopVar: true, depth: 0 });
      return;
    }
    out.push({ kind: "decl", names, start, rhsStart: j, rhsEnd: j, effect: j, noInit: true, depth: 0 });
    if (b.charAt(j) === ",") {
      i = j + 1;
      continue;
    }
    return;
  }
}

function inSpans(spans: ReadonlyArray<readonly [number, number]>, at: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const s = spans[mid];
    if (!s) return false;
    if (at < s[0]) hi = mid - 1;
    else if (at >= s[1]) lo = mid + 1;
    else return true;
  }
  return false;
}

function collectSites(src: Source): Site[] {
  const b = src.bare;
  const from = 0;
  const to = b.length;
  const sites: Site[] = [];
  const declSpans: Array<[number, number]> = [];
  const run = (re: RegExp, each: (m: RegExpExecArray) => void): void => {
    const r = new RegExp(re.source, "g");
    r.lastIndex = from;
    for (let m = r.exec(b); m && m.index < to; m = r.exec(b)) each(m);
  };
  run(DECL, (m) => {
    scanDeclarators(src, m.index + m[0].length, m.index, sites, declSpans);
  });
  declSpans.sort((x, y) => x[0] - y[0]);
  run(ASSIGN, (m) => {
    const eq = m.index + m[0].length - 1;
    if (inSpans(declSpans, m.index) || inSpans(declSpans, eq)) return;
    if (!/\s/.test(b.charAt(eq - 1)) && b.charAt(eq + 1) === "{" && !m[3]) return;
    let k = m.index;
    while (k > 0 && /[ \t]/.test(b.charAt(k - 1))) k--;
    if (/\b(?:type|interface|enum|class|import|function)\s*$/.test(b.slice(Math.max(0, k - 12), k))) return;
    const rhsStart = skipWs(b, eq + 1);
    const rhsEnd = exprEnd(src, rhsStart, true);
    sites.push({
      kind: m[2] ? "member" : "assign",
      names: [m[1] ?? ""],
      start: m.index,
      rhsStart,
      rhsEnd,
      effect: rhsEnd,
      compound: Boolean(m[3]),
      depth: 0,
    });
  });
  run(DESTRUCT_ASSIGN, (m) => {
    const patStart = m.index + m[0].indexOf(m[1] ?? "");
    if (inSpans(declSpans, patStart)) return;
    const eq = m.index + m[0].length - 1;
    const rhsStart = skipWs(b, eq + 1);
    const rhsEnd = exprEnd(src, rhsStart, true);
    sites.push({ kind: "assign", names: parseBindingNames(m[1] ?? ""), start: patStart, rhsStart, rhsEnd, effect: rhsEnd, depth: 0 });
  });
  run(CALLBACK, (m) => {
    const pos = m.index + m[0].length;
    const init = readFunctionAt(src, pos);
    if (!init) return;
    const names = parseParams(init.params).flatMap((p) => [...p.names]);
    if (names.length === 0) return;
    sites.push({
      kind: "cb",
      names,
      start: pos,
      rhsStart: m.index,
      rhsEnd: m.index + (m[1] ?? "").length,
      effect: pos,
      until: init.end,
      loopVar: true,
      depth: 0,
    });
  });
  sites.sort((x, y) => x.start - y.start || x.effect - y.effect);
  annotateDepth(src, sites, 0);
  return sites;
}

/** Fills `depth` (number of enclosing `{`) and clamps block scope of let/const to their enclosing block. */
function annotateDepth(src: Source, sites: Site[], from: number): void {
  const b = src.bare;
  const stack: number[] = [];
  let pos = from;
  for (const s of sites) {
    for (; pos < s.start; pos++) {
      const c = b.charCodeAt(pos);
      if (c === 123) stack.push(pos);
      else if (c === 125) stack.pop();
    }
    s.depth = stack.length;
    if (s.kind === "decl" && s.until === undefined && stack.length > 0) {
      const top = stack[stack.length - 1] ?? 0;
      const e = matchClose(src, top);
      if (e > 0 && isBlockScoped(b, s)) s.until = e;
    }
  }
}

function isBlockScoped(b: string, s: Site): boolean {
  let k = s.start;
  const kw = /^(const|let|var)\b/.exec(b.slice(k, k + 6));
  if (kw) return kw[1] !== "var";
  // later declarators of a multi-declaration: look back for the keyword
  k = Math.max(0, s.start - 400);
  const found = [...b.slice(k, s.start).matchAll(/\b(const|let|var)\s/g)].pop();
  return found ? found[1] !== "var" : true;
}

interface FileSites {
  readonly all: Site[];
  /** Sites outside every function unit (visible to all units). */
  readonly module: Site[];
}

const sitesCache = new WeakMap<Source, FileSites>();

function fileSites(src: Source): FileSites {
  const cached = sitesCache.get(src);
  if (cached) return cached;
  const all = collectSites(src);
  const ranges = findUnits(src)
    .map((u) => [u.start, u.end] as const)
    .sort((x, y) => x[0] - y[0]);
  const merged: Array<[number, number]> = [];
  for (const [s, e] of ranges) {
    const last = merged[merged.length - 1];
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  const module = all.filter((site) => !inSpans(merged, site.start));
  const result = { all, module };
  sitesCache.set(src, result);
  return result;
}

/** Sites whose start lies in [from, to) (binary search; `sites` is sorted by start). */
function sitesWithin(sites: readonly Site[], from: number, to: number): Site[] {
  let lo = 0;
  let hi = sites.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((sites[mid]?.start ?? 0) < from) lo = mid + 1;
    else hi = mid;
  }
  const out: Site[] = [];
  for (let k = lo; k < sites.length && (sites[k]?.start ?? 0) < to; k++) out.push(sites[k] as Site);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Seeds

const NOT_REQUEST_FIRST_PARAM = new Set(["c", "ctx", "context", "res", "reply", "response", "resp", "next", "env", "_"]);
const REQUESTISH = new Set(["params", "url", "request", "req", "query", "body", "searchParams", "headers", "cookies", "formData"]);

function seedNames(unit: FunctionUnit): Array<[string, string]> {
  const params = parseParams(unit.params);
  const out: Array<[string, string]> = [];
  if (unit.action) {
    for (const p of params) for (const n of p.names) out.push([n, `server action parameter ${n}`]);
    return out;
  }
  if (!unit.role) return out;
  const p0 = params[0];
  if (p0) {
    for (const n of p0.names) {
      if (p0.destructured ? REQUESTISH.has(n) : !NOT_REQUEST_FIRST_PARAM.has(n)) out.push([n, `request parameter ${n}`]);
    }
  }
  const p1 = params[1];
  if (unit.role === "route" && p1) for (const n of p1.names) out.push([n, `route params ${n}`]);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Analysis

interface Ev {
  readonly at: number;
  readonly until?: number;
  readonly tainted: boolean;
  readonly origin?: string;
  readonly depth: number;
  readonly loopVar: boolean;
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function compileSources(extra: ReadonlyArray<RegExp | string>): SourcePattern[] {
  const list: SourcePattern[] = [...REQUEST_SOURCES];
  extra.forEach((e, i) => {
    const re = typeof e === "string" ? new RegExp(`${L}${escapeRe(e)}(?![\\w$])`) : new RegExp(e.source, e.flags.replace("g", ""));
    list.push({ id: `extra-${i}`, label: typeof e === "string" ? e : e.source, re });
  });
  return list;
}

export function analyzeTaint(src: Source, unit: FunctionUnit, spec: TaintSpec = {}): TaintAnalysis {
  const sanitizers = [...(spec.sanitizers ?? DEFAULT_SANITIZERS), ...(spec.extraSanitizers ?? [])];
  const sources = compileSources(spec.extraSources ?? []);
  const events = new Map<string, Ev[]>();

  const stateAt = (name: string, q: number, endMode: boolean): Ev | undefined => {
    const list = events.get(name);
    if (!list) return undefined;
    for (let k = list.length - 1; k >= 0; k--) {
      const ev = list[k];
      if (!ev || ev.at > q) continue;
      if (ev.until !== undefined && q >= ev.until && !(endMode && ev.loopVar)) continue;
      return ev;
    }
    return undefined;
  };
  const addEvent = (name: string, ev: Ev): void => {
    const list = events.get(name) ?? [];
    list.push(ev);
    if (list.length > 1 && (list[list.length - 2]?.at ?? 0) > ev.at) list.sort((x, y) => x.at - y.at);
    events.set(name, list);
  };

  const evalBare = (text: string, q: number, endMode: boolean, code: string = text): { tainted: boolean; origin?: string } => {
    const neutral = neutralize(text, sanitizers, code);
    for (const s of sources) {
      const m = s.re.exec(neutral);
      if (m) return { tainted: true, origin: m[0].replace(/\s+/g, "").replace(/\($/, "") };
    }
    const re = new RegExp(IDENT.source, "g");
    for (let m = re.exec(neutral); m; m = re.exec(neutral)) {
      if (isObjectKey(neutral, m.index, m.index + m[0].length)) continue;
      const ev = stateAt(m[0], q, endMode);
      if (ev?.tainted) return { tainted: true, origin: ev.origin ?? m[0] };
    }
    return { tainted: false };
  };

  for (const [name, origin] of seedNames(unit)) if (spec.seedParams !== false) addEvent(name, { at: unit.start, tainted: true, origin, depth: 0, loopVar: false });
  for (const name of spec.taintedNames ?? []) addEvent(name, { at: unit.start, tainted: true, origin: `caller-supplied ${name}`, depth: 0, loopVar: false });

  const file = fileSites(src);
  const sites = [...file.module, ...sitesWithin(file.all, unit.start, unit.end)].sort((x, y) => x.start - y.start || x.effect - y.effect);
  for (const site of sites) {
    const r = site.noInit ? { tainted: false } : evalBare(src.bare.slice(site.rhsStart, site.rhsEnd), site.start, false, src.code.slice(site.rhsStart, site.rhsEnd));
    for (const name of site.names) {
      if (name === "") continue;
      let tainted = r.tainted;
      let origin = "origin" in r ? r.origin : undefined;
      const prev = stateAt(name, site.start, false);
      if (site.compound && prev?.tainted) {
        tainted = true;
        origin = origin ?? prev.origin;
      }
      if (site.kind === "member") {
        if (tainted) addEvent(name, { at: site.effect, tainted, origin, depth: site.depth, loopVar: false });
        continue;
      }
      if (site.kind === "assign" && !tainted && prev?.tainted && site.depth > prev.depth) continue;
      addEvent(name, { at: site.effect, until: site.until, tainted, origin, depth: site.depth, loopVar: Boolean(site.loopVar) });
    }
  }

  const bodyEnd = src.bare.charAt(unit.bodyStart) === "{" ? matchClose(src, unit.bodyStart) : -1;
  const end = Math.max(unit.start, (bodyEnd > 0 ? bodyEnd : unit.end) - 1);
  const q = (at?: number): number => at ?? end;
  return {
    isTainted(exprText, atOffset) {
      const expr = createSource("expr.ts", exprText);
      return evalBare(expr.bare, q(atOffset), atOffset === undefined, expr.code).tainted;
    },
    taintedNames(atOffset) {
      const out = new Set<string>();
      for (const name of events.keys()) if (stateAt(name, q(atOffset), atOffset === undefined)?.tainted) out.add(name);
      return out;
    },
    originOf(name, atOffset) {
      const ev = stateAt(name, q(atOffset), atOffset === undefined);
      return ev?.tainted ? (ev.origin ?? name) : undefined;
    },
  };
}
