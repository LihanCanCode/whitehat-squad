import { classifyPath, fileDirectives, hasInlineUseServer, routeFromPath } from "./facts.js";
import { readFunctionAt, readWrappedFunction, skipReturnType } from "./functions.js";
import type { Source } from "./lexer.js";
import { findRouteRegistrations } from "./routes.js";
import { matchClose, skipWs, typeAnnotationEquals } from "./scan.js";
import type { Span } from "./scan.js";

export type UnitKind = "function" | "arrow" | "method" | "handler";
export type UnitRole = "route" | "pagesApi" | "middleware" | "registration" | "action";

export interface FunctionUnit {
  /** Local name (or "default" for anonymous default exports, "GET /path" for inline route callbacks). */
  readonly name: string;
  readonly kind: UnitKind;
  readonly exported: boolean;
  /** Names it is exported under ("default", "GET", an alias...). */
  readonly exportedAs?: readonly string[];
  /** "GET"/"POST"/... for route methods and Express registrations; "USE" for app.use; "ALL" for app.all. */
  readonly httpMethod?: string;
  /** URL path (Next route/pages-api path, or the registration's path literal). */
  readonly route?: string;
  /** Start of the declaration / registration call. */
  readonly start: number;
  /** Exclusive end. */
  readonly end: number;
  /** `{` of a block body, otherwise the first character of the expression body. */
  readonly bodyStart: number;
  /** Parameter list text between the parentheses (from `code`). */
  readonly params: string;
  /** True for Server Actions (exported function in a "use server" file, or inline "use server"). */
  readonly action?: boolean;
  /** Why this is a request handler (absent for plain functions). */
  readonly role?: UnitRole;
  /** Registration receiver ("app", "router", ...). */
  readonly receiver?: string;
  /** Additional ranges that belong to this unit's behaviour (e.g. the registration with its middleware). */
  readonly extraRanges?: readonly Span[];
}

interface Draft {
  name: string;
  kind: UnitKind;
  exported: boolean;
  exportedAs: string[];
  httpMethod?: string;
  route?: string;
  start: number;
  end: number;
  bodyStart: number;
  params: string;
  action?: boolean;
  role?: UnitRole;
  receiver?: string;
  extraRanges?: Span[];
  refs?: string[];
}

interface Alias {
  readonly local: string;
  readonly exported: string;
}

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const NOT_METHODS = new Set([
  "if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "await", "new", "super", "import", "delete", "void",
  "throw", "yield", "in", "of", "else", "case", "do", "instanceof", "async", "require", "constructor_",
]);
const PREV_WORD_BLOCKS = new Set(["function", "new", "return", "typeof", "await", "in", "of", "else", "case", "delete", "void", "throw", "yield", "instanceof", "extends"]);

const FUNC_DECL = /(?<![\w$.])(?:export\s+(?:default\s+)?)?(?:async\s+)?function\b\s*\*?\s*([A-Za-z_$][\w$]*)?/g;
const VAR_DECL = /(?<![\w$.])(?:(export)\s+)?(?:declare\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?=[:=!])/g;
const METHOD_CALL = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:<[^()]*?>)?\s*\(/g;
const EXPORT_DEFAULT = /\bexport\s+default\s+(?!(?:async\s+)?function\b|class\b|abstract\b|interface\b|type\b)/g;
const CJS_EXPORT = /(?<![\w$.])(?:module\s*\.\s*)?exports(?:\s*\.\s*([A-Za-z_$][\w$]*))?\s*=(?![=>])/g;
const EXPORT_CLAUSE = /\bexport\s*(?:type\s*)?\{([^}]*)\}(?!\s*from)/g;
const IDENT_STMT = /([A-Za-z_$][\w$]*)\s*(?:;|\n|$)/y;

const cache = new WeakMap<Source, readonly FunctionUnit[]>();

class Collector {
  private readonly byBody = new Map<number, { d: Draft; p: number }>();
  readonly extra: Draft[] = [];
  readonly aliases: Alias[] = [];

  add(d: Draft, priority: number): void {
    const prev = this.byBody.get(d.bodyStart);
    if (prev && prev.p >= priority) {
      prev.d.exported = prev.d.exported || d.exported;
      for (const e of d.exportedAs) if (!prev.d.exportedAs.includes(e)) prev.d.exportedAs.push(e);
      return;
    }
    this.byBody.set(d.bodyStart, { d, p: priority });
  }

  drafts(): Draft[] {
    return [...[...this.byBody.values()].map((v) => v.d), ...this.extra];
  }
}

function collectFunctionDecls(src: Source, out: Collector): void {
  const b = src.bare;
  for (const m of b.matchAll(FUNC_DECL)) {
    const isDefault = /^export\s+default/.test(m[0]);
    const name = m[1];
    if (!name && !isDefault) continue;
    const prefix = /^export\s+(?:default\s+)?/.exec(m[0])?.[0].length ?? 0;
    const init = readFunctionAt(src, m.index + prefix);
    if (!init) continue;
    const exported = m[0].startsWith("export");
    out.add(
      {
        name: name ?? "default",
        kind: "function",
        exported,
        exportedAs: exported ? (isDefault ? ["default"] : [name ?? ""]) : [],
        start: m.index,
        end: init.end,
        bodyStart: init.bodyStart,
        params: init.params,
      },
      2,
    );
  }
}

function collectVariableFunctions(src: Source, out: Collector): void {
  const b = src.bare;
  for (const m of b.matchAll(VAR_DECL)) {
    const name = m[2] ?? "";
    let i = skipWs(b, m.index + m[0].length);
    if (b.charAt(i) === "!") i = skipWs(b, i + 1);
    if (b.charAt(i) === ":") {
      i = typeAnnotationEquals(src, i);
      if (i < 0) continue;
    }
    if (b.charAt(i) !== "=" || b.charAt(i + 1) === "=") continue;
    const pos = skipWs(b, i + 1);
    const exported = Boolean(m[1]);
    const wrapped = readWrappedFunction(src, pos);
    if (wrapped?.init) {
      out.add(
        {
          name,
          kind: wrapped.init.kind,
          exported,
          exportedAs: exported ? [name] : [],
          start: m.index,
          end: wrapped.end,
          bodyStart: wrapped.init.bodyStart,
          params: wrapped.init.params,
          refs: wrapped.refs.length > 0 ? [...wrapped.refs] : undefined,
        },
        3,
      );
      continue;
    }
    if (!exported) continue;
    const alias = IDENT_STMT;
    alias.lastIndex = pos;
    const am = alias.exec(b);
    if (am?.[1]) {
      out.aliases.push({ local: am[1], exported: name });
      continue;
    }
    if (wrapped && wrapped.refs.length > 0) {
      out.add(
        { name, kind: "arrow", exported, exportedAs: [name], start: m.index, end: wrapped.end, bodyStart: pos, params: "", refs: [...wrapped.refs] },
        3,
      );
    }
  }
}

function collectMethods(src: Source, out: Collector): void {
  const b = src.bare;
  for (const m of b.matchAll(METHOD_CALL)) {
    const name = m[1] ?? "";
    if (NOT_METHODS.has(name)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close < 0) continue;
    const body = skipReturnType(src, close);
    if (body < 0) continue;
    let k = m.index;
    while (k > 0 && /\s/.test(b.charAt(k - 1))) k--;
    const before = b.charAt(k - 1);
    if (before === "=" || before === "(") continue;
    const prevWord = /([A-Za-z_$][\w$]*)$/.exec(b.slice(Math.max(0, k - 12), k))?.[1];
    if (prevWord && PREV_WORD_BLOCKS.has(prevWord)) continue;
    const end = matchClose(src, body);
    if (end < 0) continue;
    out.add({ name, kind: "method", exported: false, exportedAs: [], start: m.index, end, bodyStart: body, params: src.code.slice(open + 1, close - 1) }, 1);
  }
}

function parseObjectExports(text: string, out: Alias[]): void {
  for (const part of text.split(",")) {
    const seg = part.trim();
    if (seg === "") continue;
    const [a, c] = seg.split(":").map((s) => s.trim());
    if (!a) continue;
    if (c && /^[A-Za-z_$][\w$]*$/.test(c)) out.push({ local: c, exported: a });
    else if (/^[A-Za-z_$][\w$]*$/.test(a)) out.push({ local: a, exported: a });
  }
}

function collectDefaultAndCjs(src: Source, out: Collector): void {
  const b = src.bare;
  for (const m of b.matchAll(EXPORT_DEFAULT)) {
    const pos = m.index + m[0].length;
    IDENT_STMT.lastIndex = pos;
    const am = IDENT_STMT.exec(b);
    if (am?.[1]) {
      out.aliases.push({ local: am[1], exported: "default" });
      continue;
    }
    const wrapped = readWrappedFunction(src, pos);
    if (!wrapped || (!wrapped.init && wrapped.refs.length === 0)) continue;
    out.add(
      {
        name: "default",
        kind: wrapped.init?.kind ?? "arrow",
        exported: true,
        exportedAs: ["default"],
        start: m.index,
        end: wrapped.end,
        bodyStart: wrapped.init?.bodyStart ?? pos,
        params: wrapped.init?.params ?? "",
        refs: wrapped.refs.length > 0 ? [...wrapped.refs] : undefined,
      },
      3,
    );
  }
  for (const m of b.matchAll(CJS_EXPORT)) {
    const prop = m[1];
    const exportedName = prop ?? "default";
    const pos = skipWs(b, m.index + m[0].length);
    IDENT_STMT.lastIndex = pos;
    const am = IDENT_STMT.exec(b);
    if (am?.[1]) {
      out.aliases.push({ local: am[1], exported: exportedName });
      continue;
    }
    if (b.charAt(pos) === "{" && !prop) {
      const close = matchClose(src, pos);
      if (close > 0) parseObjectExports(b.slice(pos + 1, close - 1), out.aliases);
      continue;
    }
    const wrapped = readWrappedFunction(src, pos);
    if (!wrapped?.init) continue;
    out.add(
      {
        name: prop ?? "default",
        kind: wrapped.init.kind,
        exported: true,
        exportedAs: [exportedName],
        start: m.index,
        end: wrapped.end,
        bodyStart: wrapped.init.bodyStart,
        params: wrapped.init.params,
        refs: wrapped.refs.length > 0 ? [...wrapped.refs] : undefined,
      },
      3,
    );
  }
  for (const m of b.matchAll(EXPORT_CLAUSE)) {
    for (const part of (m[1] ?? "").split(",")) {
      const seg = part.trim().replace(/^type\s+/, "");
      if (seg === "") continue;
      const [local, exported] = seg.split(/\s+as\s+/);
      if (local) out.aliases.push({ local, exported: exported ?? local });
    }
  }
}

function resolveAliases(drafts: Draft[], aliases: readonly Alias[]): void {
  for (const a of aliases) {
    const target = drafts.find((d) => d.name === a.local && d.kind !== "method" && d.role === undefined);
    if (!target) continue;
    target.exported = true;
    if (!target.exportedAs.includes(a.exported)) target.exportedAs.push(a.exported);
  }
}

function resolveRefs(drafts: Draft[]): void {
  for (const d of drafts) {
    if (!d.refs) continue;
    for (const ref of d.refs) {
      const target = drafts.find((t) => t.name === ref && t !== d && t.kind !== "method" && t.role === undefined);
      if (!target) continue;
      (d.extraRanges ??= []).push({ start: target.start, end: target.end });
      if (d.params === "") {
        d.params = target.params;
        d.bodyStart = target.bodyStart;
      }
    }
  }
}

function applyFileRoles(src: Source, drafts: Draft[]): Draft[] {
  const pathKind = classifyPath(src.path);
  const route = routeFromPath(src.path);
  const dir = fileDirectives(src);
  const added: Draft[] = [];
  for (const d of drafts) {
    if (d.kind === "method") continue;
    if (pathKind === "route") {
      const names = d.exportedAs.filter((n) => HTTP_METHODS.has(n));
      names.forEach((method, idx) => {
        const target = idx === 0 ? d : { ...d, exportedAs: [...d.exportedAs] };
        target.kind = "handler";
        target.role = "route";
        target.httpMethod = method;
        target.route = route;
        if (idx > 0) added.push(target);
      });
    } else if (pathKind === "pagesApi") {
      if (d.exportedAs.includes("default")) Object.assign(d, { kind: "handler", role: "pagesApi", route } satisfies Partial<Draft>);
    } else if (pathKind === "middleware") {
      if (d.exportedAs.some((n) => n === "middleware" || n === "proxy" || n === "default")) Object.assign(d, { kind: "handler", role: "middleware" } satisfies Partial<Draft>);
    } else if (dir.useServer && d.exported && d.role === undefined) {
      d.action = true;
      d.role = "action";
    }
    if (!d.action && d.role === undefined && hasInlineUseServer(src, d.bodyStart)) {
      d.action = true;
      d.role = "action";
    }
  }
  return [...drafts, ...added];
}

function registrationDrafts(src: Source, drafts: Draft[]): Draft[] {
  const out: Draft[] = [];
  for (const reg of findRouteRegistrations(src)) {
    if (reg.handlerArg < 0) continue;
    const arg = reg.args[reg.handlerArg];
    if (!arg) continue;
    const method = reg.method.toUpperCase();
    const base: Draft = {
      name: `${reg.method} ${reg.route ?? ""}`.trim(),
      kind: "handler",
      exported: false,
      exportedAs: [],
      httpMethod: method,
      route: reg.route,
      start: reg.start,
      end: reg.end,
      bodyStart: reg.start,
      params: "",
      role: "registration",
      receiver: reg.receiver,
    };
    const inline = readFunctionAt(src, arg.start);
    if (inline) {
      out.push({ ...base, bodyStart: inline.bodyStart, params: inline.params });
      continue;
    }
    const ident = src.bare.slice(arg.start, arg.end);
    const target = drafts.find((d) => d.name === ident && d.kind !== "method");
    if (target) {
      out.push({
        ...base,
        name: ident,
        start: target.start,
        end: target.end,
        bodyStart: target.bodyStart,
        params: target.params,
        extraRanges: [{ start: reg.start, end: reg.end }],
      });
    } else {
      out.push({ ...base, name: ident });
    }
  }
  return out;
}

function build(src: Source): readonly FunctionUnit[] {
  const out = new Collector();
  collectFunctionDecls(src, out);
  collectVariableFunctions(src, out);
  collectMethods(src, out);
  collectDefaultAndCjs(src, out);
  let drafts = out.drafts();
  resolveAliases(drafts, out.aliases);
  resolveRefs(drafts);
  drafts = applyFileRoles(src, drafts);
  drafts = [...drafts, ...registrationDrafts(src, drafts)];
  drafts.sort((a, b) => a.start - b.start || b.end - a.end);
  return drafts.map((d): FunctionUnit => {
    const { refs: _refs, exportedAs, extraRanges, ...rest } = d;
    return { ...rest, ...(exportedAs.length > 0 ? { exportedAs } : {}), ...(extraRanges ? { extraRanges } : {}) };
  });
}

/**
 * Every function-like unit in the file (declarations, const-bound arrows/function expressions, methods,
 * export-default/CJS exports, and Express/Hono/Fastify/Koa route callbacks), sorted by start. Units may
 * nest or overlap (a handler registered by name appears both as the function and as a handler). Cached.
 */
export function findUnits(src: Source): readonly FunctionUnit[] {
  const cached = cache.get(src);
  if (cached) return cached;
  const units = build(src);
  cache.set(src, units);
  return units;
}

/** Request-handling units: route methods, pages/api default export, middleware, server actions and route-registration callbacks. */
export function handlerUnits(src: Source): readonly FunctionUnit[] {
  return findUnits(src).filter((u) => u.kind === "handler" || u.action === true);
}

/** Innermost unit containing `offset` (ties prefer handlers). */
export function unitAt(units: readonly FunctionUnit[], offset: number): FunctionUnit | undefined {
  let best: FunctionUnit | undefined;
  for (const u of units) {
    if (offset < u.start || offset >= u.end) continue;
    if (!best) best = u;
    else {
      const size = u.end - u.start;
      const bestSize = best.end - best.start;
      if (size < bestSize || (size === bestSize && u.kind === "handler")) best = u;
    }
  }
  return best;
}

/** Source text of a unit in both views. */
export function unitBody(src: Source, unit: FunctionUnit): { code: string; bare: string } {
  return { code: src.code.slice(unit.start, unit.end), bare: src.bare.slice(unit.start, unit.end) };
}
