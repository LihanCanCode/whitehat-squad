import { makeFinding } from "../../core/finding.js";
import type { Confidence, Finding, Severity } from "../../core/types.js";
import {
  analyzeTaint,
  classifyFile,
  createSource,
  exprEnd,
  fileDirectives,
  findUnits,
  handlerUnits,
  lineOf,
  lineText,
  matchClose,
  snippetAt,
  splitArgs,
} from "../../core/source/index.js";
import type { FunctionUnit, Source, Span, TaintAnalysis } from "../../core/source/index.js";

export const AGENT_ID = "injection-hunter";

export const OWASP = {
  sql: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
  command: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
  ssrf: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
  redirect: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
  path: "https://owasp.org/www-community/attacks/Path_Traversal",
  injection: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
  input: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
} as const;

/** Facts about the whole project that individual rules consult. */
export interface ProjectFacts {
  /** express-mongo-sanitize / mongo-sanitize / mongoose sanitizeFilter appears somewhere. */
  readonly sanitizesMongo: boolean;
}

export interface FileCtx {
  readonly path: string;
  readonly src: Source;
  /** A browser-only file: "use client", or a React component using hooks outside any server entry. */
  readonly isClient: boolean;
  readonly project: ProjectFacts;
  /** The function that scopes taint for `offset` (innermost handler, else outermost function, else module). */
  unitAt(offset: number): FunctionUnit;
  taintFor(unit: FunctionUnit, client?: boolean): TaintAnalysis;
}

/** Request-like expressions that only exist in browser code (used by the redirect and eval rules). */
const CLIENT_SOURCES: readonly RegExp[] = [
  /(?<![\w$])useSearchParams\s*\(/,
  /(?<![\w$])useParams\s*\(/,
  /(?<![\w$.])(?:window\s*\.\s*)?location\s*\.\s*(?:search|hash)\b/,
  /(?<![\w$])(?:router|Router)\s*\.\s*query\b/,
];

const HOOKS = /(?<![\w$.])use(?:State|Effect|Ref|Callback|Memo|Navigate|Router|Form|Context)\s*\(/;

export function createCtx(path: string, raw: string, project: ProjectFacts): FileCtx {
  const src = createSource(path, raw);
  const kind = classifyFile(src);
  const isClient = kind === "client" || fileDirectives(src).useClient || (HOOKS.test(src.bare) && !["route", "action", "pagesApi", "express", "middleware"].includes(kind));
  const units = findUnits(src);
  const handlers = new Set(handlerUnits(src));
  const moduleUnit = { name: "<module>", kind: "function", exported: false, start: 0, end: src.raw.length, bodyStart: 0, params: "" } as FunctionUnit;
  const cache = new Map<string, TaintAnalysis>();
  return {
    path,
    src,
    isClient,
    project,
    unitAt(offset) {
      let handler: FunctionUnit | undefined;
      let outer: FunctionUnit | undefined;
      for (const u of units) {
        if (offset < u.start || offset >= u.end) continue;
        if (handlers.has(u) && (!handler || u.start >= handler.start)) handler = u;
        if (!outer || u.start < outer.start) outer = u;
      }
      return handler ?? outer ?? moduleUnit;
    },
    taintFor(unit, client = false) {
      const key = `${unit.start}:${unit.end}:${client ? 1 : 0}`;
      let t = cache.get(key);
      if (!t) {
        t = analyzeTaint(src, unit, client ? { extraSources: CLIENT_SOURCES } : {});
        cache.set(key, t);
      }
      return t;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Calls

export interface Call {
  /** Offset of the start of the match. */
  readonly index: number;
  /** Offset of the `(`. */
  readonly open: number;
  /** Offset just past the matching `)`. */
  readonly close: number;
  readonly match: RegExpExecArray;
  readonly args: readonly Span[];
}

/**
 * Calls matching `re` (which must end with `\(`). Matching runs on the `code` view but a match only counts when
 * its first character is real code, so strings and comments never produce sinks.
 */
export function findCalls(ctx: FileCtx, re: RegExp): Call[] {
  const { code, bare } = ctx.src;
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const out: Call[] = [];
  for (let m = rx.exec(code); m; m = rx.exec(code)) {
    const lead = m.index + (m[0].length - m[0].trimStart().length);
    if (bare[lead] !== code[lead]) continue;
    const open = m.index + m[0].length - 1;
    const close = matchClose(ctx.src, open);
    if (close < 0 || bare[open] !== "(") continue;
    out.push({ index: m.index, open, close, match: m, args: splitArgs(ctx.src, open + 1, close - 1) });
  }
  return out;
}

export const codeOf = (ctx: FileCtx, s: Span): string => ctx.src.code.slice(s.start, s.end);
export const bareOf = (ctx: FileCtx, s: Span): string => ctx.src.bare.slice(s.start, s.end);

// ---------------------------------------------------------------------------------------------
// String expression pieces

export interface Piece {
  readonly kind: "lit" | "expr";
  /** Literal text (kind "lit") or expression source (kind "expr"). */
  readonly text: string;
  /** Expression with strings blanked (kind "expr"), for taint checks. */
  readonly bare: string;
  readonly start: number;
}

const WS = /\s/;

function skipTemplate(src: Source, from: number): number {
  const b = src.bare;
  let i = from + 1;
  while (i < b.length) {
    const c = b[i];
    if (c === "`") return i + 1;
    if (c === "$" && b[i + 1] === "{") {
      const e = matchClose(src, i + 1);
      if (e < 0) return b.length;
      i = e;
      continue;
    }
    i++;
  }
  return b.length;
}

/** Top-level `+` separated terms of [from, to). */
function splitPlus(src: Source, from: number, to: number): Span[] {
  const b = src.bare;
  const out: Span[] = [];
  let start = from;
  let i = from;
  while (i < to) {
    const c = b[i];
    if (c === "(" || c === "[" || c === "{") {
      const e = matchClose(src, i);
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c === "`") {
      i = skipTemplate(src, i);
      continue;
    }
    if (c === "+" && b[i + 1] !== "+" && b[i + 1] !== "=" && b[i - 1] !== "+") {
      out.push({ start, end: i });
      start = i + 1;
    }
    i++;
  }
  out.push({ start, end: to });
  return out.map((s) => trim(src, s)).filter((s) => s.end > s.start);
}

function trim(src: Source, s: Span): Span {
  let a = s.start;
  let e = s.end;
  while (a < e && WS.test(src.bare[a] ?? "")) a++;
  while (e > a && WS.test(src.bare[e - 1] ?? "")) e--;
  return { start: a, end: e };
}

function templatePieces(src: Source, s: Span): Piece[] {
  const { code, bare } = src;
  const out: Piece[] = [];
  let lit = "";
  let litStart = s.start + 1;
  let i = s.start + 1;
  while (i < s.end - 1) {
    if (bare[i] === "$" && bare[i + 1] === "{") {
      const close = matchClose(src, i + 1);
      if (close < 0) break;
      if (lit) out.push({ kind: "lit", text: lit, bare: "", start: litStart });
      lit = "";
      out.push({ kind: "expr", text: code.slice(i + 2, close - 1).trim(), bare: bare.slice(i + 2, close - 1).trim(), start: i + 2 });
      i = close;
      litStart = i;
      continue;
    }
    lit += code[i] ?? "";
    i++;
  }
  if (lit) out.push({ kind: "lit", text: lit, bare: "", start: litStart });
  return out;
}

/** Splits a string-building expression (template, `+` concatenation, or a single expression) into pieces. */
export function parsePieces(src: Source, s: Span): Piece[] {
  const out: Piece[] = [];
  for (const t of splitPlus(src, s.start, s.end)) {
    const c = src.bare[t.start];
    if ((c === '"' || c === "'") && src.bare[t.end - 1] === c && src.bare.indexOf(c, t.start + 1) === t.end - 1) {
      out.push({ kind: "lit", text: src.code.slice(t.start + 1, t.end - 1), bare: "", start: t.start + 1 });
    } else if (c === "`" && skipTemplate(src, t.start) === t.end) {
      out.push(...templatePieces(src, t));
    } else {
      out.push({ kind: "expr", text: src.code.slice(t.start, t.end), bare: src.bare.slice(t.start, t.end), start: t.start });
    }
  }
  return out;
}

const IDENT_ONLY = /^[A-Za-z_$][\w$]*$/;

/** Right-hand sides of every `name =` / `name +=` / `const name =` before `before`, searched in the unit, else the file. */
export function definitionsOf(ctx: FileCtx, unit: FunctionUnit, name: string, before: number): Span[] {
  const find = (from: number): Span[] => {
    const re = new RegExp(`(?<![\\w$.])(?:(?:const|let|var)\\s+)?${name.replace(/\$/g, "\\$")}\\s*(?::[^=;\\n(]+)?\\+?=(?![=>])\\s*`, "g");
    const hay = ctx.src.bare.slice(from, before);
    const found: Span[] = [];
    for (let m = re.exec(hay); m; m = re.exec(hay)) {
      const startAt = from + m.index + m[0].length;
      const end = exprEnd(ctx.src, startAt);
      if (end > startAt) found.push(trim(ctx.src, { start: startAt, end }));
    }
    return found;
  };
  const inUnit = find(unit.start);
  if (inUnit.length > 0 || unit.start === 0) return inUnit;
  return find(0);
}

/**
 * Pieces of the argument, with lone identifiers replaced by the pieces of their definitions (two levels), so
 * `let q = "..."; q += \`${x}\`; db.query(q)` is seen as the string it is.
 */
export function expandedPieces(ctx: FileCtx, unit: FunctionUnit, arg: Span, before: number): Piece[] {
  const expand = (pieces: readonly Piece[], depth: number): Piece[] =>
    pieces.flatMap((p) => {
      if (p.kind !== "expr" || depth === 0 || !IDENT_ONLY.test(p.bare)) return [p];
      const defs = definitionsOf(ctx, unit, p.bare, before);
      if (defs.length === 0) return [p];
      return defs.flatMap((d) => expand(parsePieces(ctx.src, d), depth - 1));
    });
  return expand(parsePieces(ctx.src, arg), 2);
}

// ---------------------------------------------------------------------------------------------
// Taint helpers

/** Names that say nothing about a specific value (generic request objects). */
const GENERIC_NAMES = new Set(["req", "request", "body", "query", "params", "res", "response", "data", "ctx", "this", "await", "new", "searchParams", "headers", "cookies", "formData", "event", "true", "false", "null", "undefined", "const", "let", "var"]);

/** Identifiers the argument (and, two levels deep, their definitions) is made of. */
export function relatedNames(ctx: FileCtx, unit: FunctionUnit, texts: readonly string[], before: number): Set<string> {
  const out = new Set<string>();
  const visit = (text: string, depth: number): void => {
    for (const m of text.matchAll(/[A-Za-z_$][\w$]*/g)) {
      const n = m[0];
      if (out.has(n) || GENERIC_NAMES.has(n) || n.length < 2) continue;
      out.add(n);
      if (depth > 0) for (const d of definitionsOf(ctx, unit, n, before)) visit(bareOf(ctx, d), depth - 1);
    }
  };
  for (const t of texts) visit(t, 2);
  return out;
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Evidence that the value was validated in the unit: membership in an allowlist, an anchored regex test, or a
 * well-known validator. Matched per related name, anywhere in the unit.
 */
export function isChecked(ctx: FileCtx, unit: FunctionUnit, names: ReadonlySet<string>): boolean {
  if (names.size === 0) return false;
  const code = ctx.src.code.slice(unit.start, unit.end);
  const alt = [...names].map(esc).join("|");
  const chain = String.raw`(?:[\w$]+\s*(?:\?\.|\.)\s*)*`;
  const checks = [
    new RegExp(String.raw`\.\s*(?:includes|has|indexOf)\s*\(\s*${chain}(?:${alt})\s*[,)]`),
    new RegExp(String.raw`(?<![\w$.])(?:${alt})\s+in\s+[\w$.]+`),
    new RegExp(String.raw`\/\^[^\n]*\$\/[a-z]*\s*\.\s*test\s*\(\s*${chain}(?:${alt})\s*\)`),
    new RegExp(String.raw`(?<![\w$.])(?:${alt})\s*\.\s*match\s*\(\s*\/\^`),
    new RegExp(String.raw`(?:validator\s*\.\s*)?(?:is(?:UUID|Numeric|Int|Integer|Alpha|Alphanumeric|Hexadecimal|Slug|Email)|isNaN|Number\s*\.\s*isInteger|Number\s*\.\s*isSafeInteger)\s*\(\s*${chain}(?:${alt})\b`),
  ];
  return checks.some((re) => re.test(code));
}

/** Base-URL style pieces (`origin`, `host`, ...) that come from the server's own request, not from a user field. */
export function isBasePiece(bare: string): boolean {
  const t = bare.trim();
  if (/^(?:req|request)\s*\.\s*nextUrl(?:\s*\.\s*clone\(\))?$/.test(t)) return true;
  if (/^(?:req|request)\b|searchParams|\b(?:body|query|params|headers)\b/.test(t)) return false;
  return /(?:^|\.)(?:origin|host|protocol|baseUrl|siteUrl|appUrl|APP_URL|SITE_URL|BASE_URL)\s*$/i.test(t);
}

export const isConstantPiece = (bare: string): boolean => {
  const t = bare.trim();
  return /^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)*$/.test(t) || /^[A-Z_][A-Z0-9_]*\s*\[/.test(t) || /^\d+(?:\.\d+)?$/.test(t);
};

/** `table[key]` / `table[key] ?? "id"`: a lookup into an untainted object, i.e. an allowlist by construction. */
export function isLookupPiece(bare: string, taint: TaintAnalysis, at: number): boolean {
  const m = /^\s*([\w$.]+)\s*\[[^\]]+\]\s*(?:(?:\?\?|\|\|)\s*(?:["'`][^"'`]*["'`]|[\w$]+))?\s*$/.exec(bare);
  return m !== null && !taint.isTainted(m[1] ?? "", at);
}

// ---------------------------------------------------------------------------------------------
// Findings

export interface FindingSpec {
  readonly ruleId: string;
  readonly offset: number;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence?: Confidence;
  readonly explanation: string;
  readonly summary: string;
  /** Replacement for the first line of the call, shown as a diff. */
  readonly after?: string;
  readonly config?: string;
  /** What to ask a coding agent to do; the file and line are prepended. */
  readonly prompt: string;
  readonly references: readonly string[];
  readonly cwe: string;
}

export function emit(ctx: FileCtx, s: FindingSpec): Finding {
  const line = lineOf(ctx.src, s.offset);
  const before = lineText(ctx.src, line);
  const diff = s.after ? `--- a/${ctx.path}\n+++ b/${ctx.path}\n@@ line ${line} @@\n-${before}\n+${s.after}` : undefined;
  return makeFinding({
    ruleId: s.ruleId,
    agentId: AGENT_ID,
    title: s.title,
    severity: s.severity,
    ...(s.confidence ? { confidence: s.confidence } : {}),
    explanation: s.explanation,
    evidence: [{ file: ctx.path, line, snippet: snippetAt(ctx.src, s.offset) }],
    fix: {
      summary: s.summary,
      ...(diff ? { patch: { file: ctx.path, diff } } : {}),
      ...(s.config ? { config: s.config } : {}),
      agentPrompt: `In ${ctx.path} at line ${line}: ${s.prompt}`,
      references: s.references,
    },
    target: ctx.path,
    cwe: s.cwe,
  });
}

/** Is `bare` a direct reference (identifier / member chain / `await req.json()` property), not a transformed value? */
export function isDirectRef(bare: string): boolean {
  let t = bare.trim();
  t = t.replace(/\s*(?:\?\?|\|\|)\s*[^]*$/, "").replace(/\s+as\s+[\w.<>[\]| ]+$/, "").replace(/!$/, "").trim();
  return /^[\w$]+(?:(?:\?\.|\.)[\w$]+|\[[^\]]*\])*$/.test(t) || /^\(\s*await\s+[\w$.]+\(\)\s*\)(?:\s*(?:\?\.|\.)[\w$]+)+$/.test(t);
}

/** The line of the file containing `span` with that span replaced, if it sits on one line (for diff `+` lines). */
export function replaceInLine(ctx: FileCtx, span: Span, replacement: string): string | undefined {
  const line = lineOf(ctx.src, span.start);
  if (lineOf(ctx.src, Math.max(span.start, span.end - 1)) !== line) return undefined;
  const text = lineText(ctx.src, line);
  const from = span.start - (ctx.src.lineStarts[line - 1] ?? 0);
  const to = from + (span.end - span.start);
  return `${text.slice(0, from)}${replacement}${text.slice(to)}`;
}

/** True when [start, end) lies on a single line. */
export function isOneLine(ctx: FileCtx, start: number, end: number): boolean {
  return lineOf(ctx.src, start) === lineOf(ctx.src, Math.max(start, end - 1));
}
