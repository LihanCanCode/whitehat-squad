import type { Source } from "./lexer.js";

/**
 * Structural scanning helpers that operate on `Source.bare`, where strings, comments, regex bodies and
 * template text are blanked, so brackets and separators found here are always real code.
 */

export interface Span {
  readonly start: number;
  readonly end: number;
}

const forward = new WeakMap<Source, Int32Array>();
const backward = new WeakMap<Source, Int32Array>();

function table(src: Source): Int32Array {
  const cached = forward.get(src);
  if (cached) return cached;
  const b = src.bare;
  const n = b.length;
  const t = new Int32Array(n).fill(-1);
  const stack: number[] = [];
  for (let i = 0; i < n; i++) {
    const c = b.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) {
      stack.push(i);
    } else if (c === 41 || c === 93 || c === 125) {
      const want = c === 41 ? 40 : c === 93 ? 91 : 123;
      let k = stack.length - 1;
      while (k >= 0 && b.charCodeAt(stack[k] ?? 0) !== want) k--;
      if (k < 0) continue;
      t[stack[k] ?? 0] = i + 1;
      stack.length = k;
    }
  }
  forward.set(src, t);
  return t;
}

/** Index just past the bracket matching the opener at `open` (any of `([{`), or -1. */
export function matchClose(src: Source, open: number): number {
  const v = table(src)[open];
  return v === undefined || v < 0 ? -1 : v;
}

/** Index of the opener matching the closer at `close`, or -1. */
export function matchOpen(src: Source, close: number): number {
  let rev = backward.get(src);
  if (!rev) {
    const t = table(src);
    rev = new Int32Array(t.length).fill(-1);
    for (let i = 0; i < t.length; i++) {
      const e = t[i] ?? -1;
      if (e > 0) rev[e - 1] = i;
    }
    backward.set(src, rev);
  }
  const v = rev[close];
  return v === undefined ? -1 : v;
}

export const isWs = (c: number): boolean => c === 32 || c === 9 || c === 10 || c === 13;

export function skipWs(s: string, i: number): number {
  let j = i;
  while (j < s.length && isWs(s.charCodeAt(j))) j++;
  return j;
}

/** Index after the template literal whose opening backtick is at `i` (works on `bare`). */
export function skipTemplate(src: Source, i: number): number {
  const b = src.bare;
  const n = b.length;
  const t = table(src);
  let j = i + 1;
  while (j < n) {
    const c = b.charCodeAt(j);
    if (c === 96) return j + 1;
    if (c === 36 && b.charCodeAt(j + 1) === 123) {
      const e = t[j + 1] ?? -1;
      if (e < 0) return n;
      j = e;
      continue;
    }
    j++;
  }
  return n;
}

const CONT_AFTER = new Set("+-*/%&|?:=,<>.^".split(""));
const CONT_BEFORE = new Set("+-*/%&|?:.^".split(""));

/**
 * End offset of the expression starting at `pos`: stops at `;`, `,`, an unmatched closer or a newline
 * that is not a continuation (previous token is an operator, or next line starts with `. ? : + - * / & |`).
 */
export function exprEnd(src: Source, pos: number, stopAtComma = true): number {
  const b = src.bare;
  const n = b.length;
  const t = table(src);
  let i = pos;
  let last = "";
  while (i < n) {
    const ch = b.charAt(i);
    const c = b.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) {
      const e = t[i] ?? -1;
      if (e < 0) return i;
      i = e;
      last = ")";
      continue;
    }
    if (c === 41 || c === 93 || c === 125) return i;
    if (c === 96) {
      i = skipTemplate(src, i);
      last = "`";
      continue;
    }
    if (ch === ";" || (stopAtComma && ch === ",")) return i;
    if (c === 10) {
      if (!CONT_AFTER.has(last)) {
        const k = skipWs(b, i + 1);
        if (!CONT_BEFORE.has(b.charAt(k))) return i;
      }
      i++;
      continue;
    }
    if (isWs(c)) {
      i++;
      continue;
    }
    last = ch;
    i++;
  }
  return n;
}

/** Trimmed spans of the top-level comma-separated items in `[from, to)` (trailing comma ignored). */
export function splitArgs(src: Source, from: number, to: number): Span[] {
  const b = src.bare;
  const t = table(src);
  const out: Span[] = [];
  let start = from;
  const push = (end: number): void => {
    let s = start;
    let e = end;
    while (s < e && isWs(b.charCodeAt(s))) s++;
    while (e > s && isWs(b.charCodeAt(e - 1))) e--;
    if (e > s) out.push({ start: s, end: e });
  };
  let i = from;
  while (i < to) {
    const c = b.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) {
      const e = t[i] ?? -1;
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c === 96) {
      i = skipTemplate(src, i);
      continue;
    }
    if (c === 44) {
      push(i);
      start = i + 1;
    }
    i++;
  }
  push(Math.min(i, to));
  return out;
}

/** From the `:` of a type annotation: index of the assignment `=` that ends it, or -1 (no initializer). */
export function typeAnnotationEquals(src: Source, from: number): number {
  const b = src.bare;
  let angle = 0;
  const limit = Math.min(b.length, from + 400);
  for (let j = from + 1; j < limit; j++) {
    const c = b.charAt(j);
    if (c === "(" || c === "[" || c === "{") {
      const e = matchClose(src, j);
      if (e < 0) return -1;
      j = e - 1;
    } else if (c === "=") {
      if (b.charAt(j + 1) === ">") j++;
      else if (angle === 0) return j;
    } else if (c === "<") angle++;
    else if (c === ">") angle = Math.max(0, angle - 1);
    else if (c === ";") return -1;
  }
  return -1;
}
