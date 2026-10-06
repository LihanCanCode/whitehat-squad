import type { Source } from "./lexer.js";

const DEFAULT_SNIPPET = 200;

/** 1-based line number of `offset` (binary search over `lineStarts`, O(log lines)). Clamped to the file. */
export function lineOf(src: Source, offset: number): number {
  const starts = src.lineStarts;
  let lo = 0;
  let hi = starts.length - 1;
  if (offset <= 0) return 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Text of 1-based `line` without its line terminator. Out-of-range lines give "". */
export function lineText(src: Source, line: number): string {
  if (line < 1 || line > src.lineStarts.length) return "";
  const start = src.lineStarts[line - 1] ?? 0;
  let end = line < src.lineStarts.length ? (src.lineStarts[line] ?? src.raw.length) - 1 : src.raw.length;
  if (end > start && src.raw.charAt(end - 1) === "\r") end--;
  return src.raw.slice(start, end);
}

/** The trimmed source line containing `offset`, cut to `max` characters (ending in "..."). */
export function snippetAt(src: Source, offset: number, max = DEFAULT_SNIPPET): string {
  const text = lineText(src, lineOf(src, offset)).trim();
  return text.length > max ? `${text.slice(0, Math.max(0, max - 3))}...` : text;
}
