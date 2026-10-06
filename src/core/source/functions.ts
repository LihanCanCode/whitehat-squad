import type { Source } from "./lexer.js";
import { exprEnd, matchClose, skipWs, splitArgs } from "./scan.js";

export interface FunctionInit {
  readonly kind: "function" | "arrow";
  /** Parameter list text (from `code`). */
  readonly params: string;
  /** `{` of a block body, or the first character of an expression body. */
  readonly bodyStart: number;
  /** Exclusive end of the function. */
  readonly end: number;
  readonly isAsync: boolean;
}

export interface WrappedFunction {
  /** First function found (directly or as an argument of the wrapper call(s)). */
  readonly init: FunctionInit | null;
  /** End of the whole expression (the wrapper call's `)` or the function end). */
  readonly end: number;
  /** Plain identifiers passed to the wrapper, e.g. `withAuth(handler)` -> ["handler"]. */
  readonly refs: readonly string[];
}

const ASYNC = /async\b\s*(?=[(A-Za-z_$<])/y;
const FUNCTION_KW = /function\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*(?:<[^()]*?>)?\s*(?=\()/y;
const ARROW_IDENT = /([A-Za-z_$][\w$]*)\s*=>/y;
const GENERICS = /<[^()]*?>\s*(?=\()/y;
const CALL_HEAD = /(?:new\s+)?[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*(?:<[^()]*?>)?\s*\(/y;
const MAX_WRAP_DEPTH = 4;
const MAX_TYPE_SCAN = 600;

function sticky(re: RegExp, s: string, at: number): RegExpExecArray | null {
  re.lastIndex = at;
  return re.exec(s);
}

/** From just after a parameter list's `)`: index of the body `{` (skipping a return type), or -1. */
export function skipReturnType(src: Source, from: number): number {
  const b = src.bare;
  const i = skipWs(b, from);
  if (b.charAt(i) === "{") return i;
  if (b.charAt(i) !== ":") return -1;
  let angle = 0;
  let prev = ":";
  const limit = Math.min(b.length, i + MAX_TYPE_SCAN);
  for (let j = i + 1; j < limit; j++) {
    const c = b.charAt(j);
    if (c === " " || c === "\t" || c === "\n" || c === "\r") continue;
    if (c === "(" || c === "[") {
      const e = matchClose(src, j);
      if (e < 0) return -1;
      j = e - 1;
      prev = ")";
      continue;
    }
    if (c === "{") {
      if (angle === 0 && !":|&,<(A".includes(prev)) return j;
      const e = matchClose(src, j);
      if (e < 0) return -1;
      j = e - 1;
      prev = "}";
      continue;
    }
    if (c === "=" && b.charAt(j + 1) === ">") {
      j++;
      prev = "A";
      continue;
    }
    if (c === ";" || c === "=" || c === "}" || c === ")" || c === "]") return -1;
    if (c === "<") angle++;
    else if (c === ">") angle = Math.max(0, angle - 1);
    else if (c === "," && angle === 0 && prev !== ":") return -1;
    prev = c;
  }
  return -1;
}

/** Index of the `=>` that follows a parameter list ending at `close` (return type allowed), or -1. */
function findArrow(src: Source, close: number): number {
  const b = src.bare;
  const i = skipWs(b, close);
  if (b.startsWith("=>", i)) return i;
  if (b.charAt(i) !== ":") return -1;
  let angle = 0;
  const limit = Math.min(b.length, i + MAX_TYPE_SCAN);
  for (let j = i + 1; j < limit; j++) {
    const c = b.charAt(j);
    if (c === "(" || c === "[" || c === "{") {
      const e = matchClose(src, j);
      if (e < 0) return -1;
      j = e - 1;
    } else if (c === "=" && b.charAt(j + 1) === ">") {
      if (angle === 0) return j;
      j++;
    } else if (c === "<") angle++;
    else if (c === ">") angle = Math.max(0, angle - 1);
    else if (c === ";") return -1;
  }
  return -1;
}

function arrowBody(src: Source, arrowIdx: number, params: string, isAsync: boolean): FunctionInit | null {
  const b = src.bare;
  const bodyStart = skipWs(b, arrowIdx + 2);
  if (bodyStart >= b.length) return null;
  if (b.charAt(bodyStart) === "{") {
    const end = matchClose(src, bodyStart);
    return end < 0 ? null : { kind: "arrow", params, bodyStart, end, isAsync };
  }
  return { kind: "arrow", params, bodyStart, end: Math.max(bodyStart, exprEnd(src, bodyStart)), isAsync };
}

/** Reads a function expression / arrow function starting at `pos`; null if `pos` is not one. */
export function readFunctionAt(src: Source, pos: number): FunctionInit | null {
  const b = src.bare;
  let i = skipWs(b, pos);
  let isAsync = false;
  const a = sticky(ASYNC, b, i);
  if (a) {
    isAsync = true;
    i += a[0].length;
  }
  const f = sticky(FUNCTION_KW, b, i);
  if (f) {
    const open = i + f[0].length;
    const close = matchClose(src, open);
    if (close < 0) return null;
    const bodyOpen = skipReturnType(src, close);
    if (bodyOpen < 0) return null;
    const end = matchClose(src, bodyOpen);
    if (end < 0) return null;
    return { kind: "function", params: src.code.slice(open + 1, close - 1), bodyStart: bodyOpen, end, isAsync };
  }
  const g = sticky(GENERICS, b, i);
  if (g) i += g[0].length;
  if (b.charAt(i) === "(") {
    const close = matchClose(src, i);
    if (close < 0) return null;
    const arrow = findArrow(src, close);
    if (arrow < 0) return null;
    return arrowBody(src, arrow, src.code.slice(i + 1, close - 1), isAsync);
  }
  const id = sticky(ARROW_IDENT, b, i);
  if (id) return arrowBody(src, i + id[0].length - 2, id[1] ?? "", isAsync);
  return null;
}

/** Like {@link readFunctionAt} but also looks through wrapper calls: `withAuth(async (req) => {...})`. */
export function readWrappedFunction(src: Source, pos: number, depth = 0): WrappedFunction | null {
  const direct = readFunctionAt(src, pos);
  if (direct) return { init: direct, end: direct.end, refs: [] };
  if (depth >= MAX_WRAP_DEPTH) return null;
  const b = src.bare;
  const start = skipWs(b, pos);
  const head = sticky(CALL_HEAD, b, start);
  if (!head) return null;
  const open = start + head[0].length - 1;
  const close = matchClose(src, open);
  if (close < 0) return null;
  let init: FunctionInit | null = null;
  const refs: string[] = [];
  for (const arg of splitArgs(src, open + 1, close - 1)) {
    const text = b.slice(arg.start, arg.end);
    if (/^[A-Za-z_$][\w$]*$/.test(text)) {
      refs.push(text);
      continue;
    }
    const inner = readWrappedFunction(src, arg.start, depth + 1);
    if (inner) {
      init = init ?? inner.init;
      refs.push(...inner.refs);
    }
  }
  return { init, end: close, refs };
}
