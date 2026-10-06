import { exprEnd, matchClose, splitArgs, unitAt, type FunctionUnit, type Source, type Span } from "../../core/source/index.js";
import type { FileCtx } from "./context.js";
import { codeMatches } from "./util.js";

/** A call expression found in real code: offsets of the call, its parentheses, and top-level arguments. */
export interface Call {
  readonly index: number;
  readonly open: number;
  readonly close: number;
  readonly args: readonly Span[];
}

/** Calls whose callee matches `re` (the regex must end with the opening parenthesis). */
export function findCalls(src: Source, re: RegExp, start = 0, end = src.code.length): Call[] {
  const out: Call[] = [];
  for (const m of codeMatches(src, re, start, end)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close < 0) continue;
    out.push({ index: m.index, open, close, args: splitArgs(src, open + 1, close - 1) });
  }
  return out;
}

export function argText(src: Source, call: Call, i: number): string {
  const a = call.args[i];
  return a ? src.code.slice(a.start, a.end).trim() : "";
}

export function callText(src: Source, call: Call): string {
  return src.code.slice(call.open + 1, call.close - 1);
}

const LITERAL = /^(["'])((?:\\.|(?!\1).)*)\1$/s;

/** Value of a plain string literal (or a template literal without interpolation), else undefined. */
export function stringLiteral(text: string): string | undefined {
  const t = text.trim();
  const m = LITERAL.exec(t);
  if (m) return m[2] ?? "";
  const tpl = /^`([^`$]*)`$/.exec(t);
  return tpl ? (tpl[1] ?? "") : undefined;
}

/** The outermost function containing `offset` (the top-level unit), or undefined at module level. */
export function outermostUnit(f: FileCtx, offset: number): FunctionUnit | undefined {
  let best: FunctionUnit | undefined;
  for (const u of f.units) {
    if (offset < u.start || offset >= u.end) continue;
    if (!best || u.end - u.start > best.end - best.start) best = u;
  }
  return best ?? unitAt(f.units, offset);
}

/** Text of the initializer of `const NAME = ...` declared in the file, if any. */
export function initializerOf(src: Source, name: string): string | undefined {
  const m = new RegExp(String.raw`\b(?:const|let|var)\s+${name.replace(/\$/g, "\$")}\s*(?::[^=;\n]+)?=(?![=>])\s*`).exec(src.code);
  if (!m || src.bare.charAt(m.index) !== src.code.charAt(m.index)) return undefined;
  const from = m.index + m[0].length;
  let end = from;
  const stop = /[;\n]/;
  while (end < src.code.length && !stop.test(src.code.charAt(end))) end++;
  return src.code.slice(from, end).trim();
}

/** Full initializer text of `const NAME = ...` (multi-line aware), or undefined. */
export function fullInitializer(src: Source, name: string): string | undefined {
  const m = new RegExp(String.raw`\b(?:const|let|var)\s+${name.replace(/\$/g, "\$")}\s*(?::[^=;\n]+)?=(?![=>])\s*`).exec(src.bare);
  if (!m) return undefined;
  const from = m.index + m[0].length;
  return src.code.slice(from, exprEnd(src, from, true));
}
