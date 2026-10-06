/**
 * Python-aware text helper. Produces a "code view" of a source file with comments and string
 * contents blanked to spaces (offsets and newlines preserved), so regexes and bracket matching on
 * the code view cannot be fooled by `#` or quotes inside strings. The `{expr}` parts of f-strings
 * are deliberately kept as code because they are where injection happens.
 *
 * Limits: no full tokenizer (no `\N{...}` handling, no line-continuation tricks inside nested
 * f-string expressions beyond simple quote skipping), and indentation-based scoping is heuristic.
 */

export interface PyString {
  /** Offset of the first prefix/quote character. */
  readonly start: number;
  /** Offset one past the closing quote. */
  readonly end: number;
  readonly isF: boolean;
  /** f-string that contains at least one `{expr}` replacement field. */
  readonly hasInterp: boolean;
  /** Raw text between the quotes (not unescaped). */
  readonly value: string;
}

const MAX_SNIPPET = 200;
const IDENT = /[A-Za-z0-9_]/;
const PREFIX = /[rRbBuUfF]{1,2}(?=["'])/y;

function blank(chars: string[], from: number, to: number): void {
  for (let i = from; i < to; i++) {
    const c = chars[i];
    if (c !== "\n" && c !== "\r") chars[i] = " ";
  }
}

/** Index one past the `}` that closes an f-string replacement field opening at `open`. */
function skipField(src: string, open: number): number {
  let depth = 0;
  let i = open;
  while (i < src.length) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    } else if (c === '"' || c === "'") {
      const close = src.indexOf(c, i + 1);
      if (close === -1) return src.length;
      i = close;
    } else if (c === "\n" && depth <= 0) return i;
    i++;
  }
  return src.length;
}

interface Scanned {
  readonly code: string;
  readonly strings: readonly PyString[];
}

/** Scan one string literal starting at `qi` (the quote). Returns the end offset. */
function scanString(
  src: string, chars: string[], strings: PyString[], start: number, qi: number, prefix: string,
): number {
  const q = src[qi] as string;
  const triple = src.startsWith(q.repeat(3), qi);
  const open = triple ? 3 : 1;
  const isF = /f/i.test(prefix);
  const isRaw = /r/i.test(prefix);
  let i = qi + open;
  let hasInterp = false;
  const bodyStart = i;
  let closeAt = -1;
  while (i < src.length) {
    const c = src[i] as string;
    if (!isRaw && c === "\\") {
      blank(chars, i, Math.min(i + 2, src.length));
      i += 2;
      continue;
    }
    if (isF && c === "{") {
      if (src[i + 1] === "{") {
        blank(chars, i, i + 2);
        i += 2;
        continue;
      }
      hasInterp = true;
      i = skipField(src, i);
      continue;
    }
    if (triple ? src.startsWith(q.repeat(3), i) : c === q) {
      closeAt = i;
      break;
    }
    if (!triple && c === "\n") break; // unterminated: stop at end of line
    blank(chars, i, i + 1);
    i++;
  }
  const end = closeAt === -1 ? i : closeAt + open;
  strings.push({
    start, end, isF, hasInterp,
    value: src.slice(bodyStart, closeAt === -1 ? i : closeAt),
  });
  return end;
}

export function scanPython(src: string): Scanned {
  const chars = src.split("");
  const strings: PyString[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === "#") {
      const nl = src.indexOf("\n", i);
      const end = nl === -1 ? src.length : nl;
      blank(chars, i, end);
      i = end;
      continue;
    }
    if (c === '"' || c === "'") {
      i = scanString(src, chars, strings, i, i, "");
      continue;
    }
    if (/[A-Za-z]/.test(c) && (i === 0 || !IDENT.test(src[i - 1] as string))) {
      PREFIX.lastIndex = i;
      const m = PREFIX.exec(src);
      if (m) {
        i = scanString(src, chars, strings, i, i + m[0].length, m[0]);
        continue;
      }
      while (i < src.length && IDENT.test(src[i] as string)) i++;
      continue;
    }
    i++;
  }
  return { code: chars.join(""), strings };
}

export class PyText {
  readonly code: string;
  readonly strings: readonly PyString[];
  private readonly lineStarts: number[];

  constructor(readonly raw: string) {
    const scanned = scanPython(raw);
    this.code = scanned.code;
    this.strings = scanned.strings;
    this.lineStarts = [0];
    for (let i = 0; i < raw.length; i++) if (raw.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
  }

  /** 1-based line number of an offset (binary search over precomputed line starts). */
  lineOf(offset: number): number {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.lineStarts[mid] as number) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  /** Raw text of a 1-based line (no trailing newline). */
  lineText(line: number): string {
    const start = this.lineStarts[line - 1];
    if (start === undefined) return "";
    const next = this.lineStarts[line];
    return this.raw.slice(start, next === undefined ? undefined : next - 1).replace(/\r$/, "");
  }

  /** The trimmed source line containing `offset`, capped at 200 chars. */
  snippet(offset: number): string {
    return this.lineText(this.lineOf(offset)).trim().slice(0, MAX_SNIPPET);
  }

  /** `# whsquad-ignore PY-001[, PY-002]` on the finding's line or the line before. */
  isSuppressed(ruleId: string, offset: number): boolean {
    const line = this.lineOf(offset);
    const re = new RegExp(`#\\s*whsquad-ignore\\b[^\\n]*\\b${ruleId}\\b`);
    return re.test(this.lineText(line)) || (line > 1 && re.test(this.lineText(line - 1)));
  }

  /** The string literal that starts at or contains `offset`, if any. */
  stringAt(offset: number): PyString | undefined {
    let lo = 0;
    let hi = this.strings.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const s = this.strings[mid] as PyString;
      if (offset < s.start) hi = mid - 1;
      else if (offset >= s.end) lo = mid + 1;
      else return s;
    }
    return undefined;
  }
}

const OPEN = "([{";
const CLOSE = ")]}";

/** Offset one past the bracket matching the one at `open` (code view). -1 when unbalanced. */
export function matchBracket(code: string, open: number): number {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const c = code[i] as string;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Top-level comma-separated argument ranges of the call whose `(` is at `open`. */
export function callArgs(code: string, open: number): { start: number; end: number }[] {
  const close = matchBracket(code, open);
  if (close === -1) return [];
  const args: { start: number; end: number }[] = [];
  let depth = 0;
  let from = open + 1;
  for (let i = open + 1; i < close - 1; i++) {
    const c = code[i] as string;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) depth--;
    else if (c === "," && depth === 0) {
      args.push({ start: from, end: i });
      from = i + 1;
    }
  }
  if (code.slice(from, close - 1).trim() !== "") args.push({ start: from, end: close - 1 });
  return args;
}

/** End of the statement starting at `start` (bracket-aware, honors `\` continuations). */
export function statementEnd(code: string, start: number): number {
  let depth = 0;
  for (let i = start; i < code.length; i++) {
    const c = code[i] as string;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) depth = Math.max(0, depth - 1);
    else if (c === "\n" && depth === 0 && code[i - 1] !== "\\") return i;
  }
  return code.length;
}

/** Code with every string literal that has no interpolation blanked out entirely (quotes too). */
export function withoutLiterals(pt: PyText, from: number, to: number): string {
  const chars = pt.code.slice(from, to).split("");
  for (const s of pt.strings) {
    if (s.end <= from || s.start >= to || s.hasInterp) continue;
    blank(chars, Math.max(s.start, from) - from, Math.min(s.end, to) - from);
  }
  return chars.join("");
}

/** True when the range builds a string dynamically (f-string, %, +, .format) from non-literals. */
export function isDynamicString(pt: PyText, from: number, to: number): boolean {
  for (const s of pt.strings) {
    if (s.hasInterp && s.start >= from && s.end <= to) return true;
  }
  const rem = withoutLiterals(pt, from, to);
  return /\.format\s*\(/.test(rem) || (/[%+]/.test(rem) && /[A-Za-z_]/.test(rem));
}
