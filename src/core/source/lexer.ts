/**
 * Single-pass JS/TS/JSX "tokenizer-lite". It does not build tokens; it classifies every character as
 * code, comment, string/template text, regex body or JSX text and produces two offset-identical views.
 *
 * Heuristics (documented limits):
 *  - Regex literal vs division is decided from the previous significant token: a regex may start after
 *    `( , = : [ ! & | ? { } ; + - * % < > ~ ^`, the keywords `return typeof instanceof in of new delete void
 *    throw case do else yield await`, or at the start of an expression. It may NOT start after an
 *    identifier, number, string, `)` or `]`. Postfix `++`/`--` count as "value" tokens. A regex that would
 *    run past the end of the line is treated as division. Known limit: `if (x) /re/.test(y)` (regex after
 *    a `)`) is read as division.
 *  - JSX is only attempted in expression position (where a regex could start) for non-`.ts` files, when
 *    `<` is followed by an identifier or `>`. The tag head is validated (only names, `=`, strings, `{}`
 *    and `/>`), and the element must close before EOF; otherwise the attempt is rolled back and `<` is an
 *    operator. JSX text (including apostrophes and `//`) is never scanned for strings or comments.
 *    Known limit: a TS generic arrow `<T extends X>(a) => a` in a `.tsx` file looks like a JSX tag; the
 *    unclosed-element check recovers from the common cases.
 */

export interface Source {
  readonly path: string;
  /** Original text. */
  readonly raw: string;
  /** Raw with comments blanked to spaces; strings, templates, regexes and JSX text kept. */
  readonly code: string;
  /**
   * Raw with comments AND string / template text / regex bodies / JSX text blanked. Quotes, backticks,
   * slashes, `${` and `}` are kept so structure stays visible; `${...}` expression parts stay code.
   */
  readonly bare: string;
  /** Offset of the first character of each line (line 1 starts at 0). */
  readonly lineStarts: readonly number[];
}

export interface LexOptions {
  /** Force JSX on/off. Default: on unless the path ends in .ts/.mts/.cts. */
  readonly jsx?: boolean;
}

const REGEX_KEYWORDS = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await",
]);

const isIdStart = (c: number): boolean =>
  (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 95 || c === 36 || (c >= 128 && c !== 0xa0 && c !== 0xfeff && c !== 0x2028 && c !== 0x2029);
const isIdPart = (c: number): boolean => isIdStart(c) || (c >= 48 && c <= 57);
const isTagNameChar = (c: number): boolean => isIdPart(c) || c === 45 || c === 46 || c === 58;

function toText(buf: Uint16Array): string {
  return Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength).toString("utf16le");
}

export function createSource(path: string, raw: string, options: LexOptions = {}): Source {
  const n = raw.length;
  const jsx = options.jsx ?? !/\.[mc]?ts$/i.test(path);
  const code = new Uint16Array(n);
  const bare = new Uint16Array(n);
  for (let k = 0; k < n; k++) {
    const c = raw.charCodeAt(k);
    code[k] = c;
    bare[k] = c;
  }
  let failPos = 0;

  const blank = (buf: Uint16Array, from: number, to: number): void => {
    const end = Math.min(to, n);
    for (let k = from; k < end; k++) {
      const c = buf[k];
      if (c !== 10 && c !== 13) buf[k] = 32;
    }
  };
  const restore = (from: number, to: number): void => {
    const end = Math.min(to, n);
    for (let k = from; k < end; k++) {
      const c = raw.charCodeAt(k);
      code[k] = c;
      bare[k] = c;
    }
  };
  const fail = (at: number): number => {
    failPos = at;
    return -1;
  };

  const lineComment = (i: number): number => {
    let j = raw.indexOf("\n", i);
    if (j < 0) j = n;
    blank(code, i, j);
    blank(bare, i, j);
    return j;
  };
  const blockComment = (i: number): number => {
    const j = raw.indexOf("*/", i + 2);
    const end = j < 0 ? n : j + 2;
    blank(code, i, end);
    blank(bare, i, end);
    return end;
  };
  const skipString = (i: number, q: number): number => {
    let j = i + 1;
    while (j < n) {
      const c = raw.charCodeAt(j);
      if (c === 92) {
        j += 2;
        continue;
      }
      if (c === q) {
        blank(bare, i + 1, j);
        return j + 1;
      }
      if (c === 10) {
        blank(bare, i + 1, j);
        return j;
      }
      j++;
    }
    blank(bare, i + 1, n);
    return n;
  };
  const scanRegex = (start: number): number => {
    let i = start + 1;
    let inClass = false;
    while (i < n) {
      const c = raw.charCodeAt(i);
      if (c === 10 || c === 13) return -1;
      if (c === 92) {
        i += 2;
        continue;
      }
      if (c === 91) inClass = true;
      else if (c === 93) inClass = false;
      else if (c === 47 && !inClass) {
        const bodyEnd = i;
        i++;
        while (i < n && isIdPart(raw.charCodeAt(i))) i++;
        blank(bare, start + 1, bodyEnd);
        return i;
      }
      i++;
    }
    return -1;
  };

  const lexTemplate = (start: number): number => {
    let i = start + 1;
    let textStart = i;
    while (i < n) {
      const c = raw.charCodeAt(i);
      if (c === 92) {
        i += 2;
        continue;
      }
      if (c === 96) {
        blank(bare, textStart, i);
        return i + 1;
      }
      if (c === 36 && raw.charCodeAt(i + 1) === 123) {
        blank(bare, textStart, i);
        const e = lexCode(i + 2, true);
        if (e >= n) return n;
        i = e + 1;
        textStart = i;
        continue;
      }
      i++;
    }
    blank(bare, textStart, n);
    return n;
  };

  /** Returns the index just past the element, or -1 (with `failPos` set) when this is not JSX. */
  const lexJsx = (start: number): number => {
    let i = start + 1;
    while (i < n && isTagNameChar(raw.charCodeAt(i))) i++;
    for (;;) {
      if (i >= n) return fail(n);
      const c = raw.charCodeAt(i);
      if (c === 62) {
        i++;
        break;
      }
      if (c === 47) {
        const d = raw.charCodeAt(i + 1);
        if (d === 62) return i + 2;
        if (d === 42) {
          i = blockComment(i);
          continue;
        }
        return fail(i);
      }
      if (c === 123) {
        const e = lexCode(i + 1, true);
        if (e >= n) return fail(n);
        i = e + 1;
        continue;
      }
      if (c === 34 || c === 39) {
        const j = raw.indexOf(c === 34 ? '"' : "'", i + 1);
        if (j < 0) return fail(n);
        blank(bare, i + 1, j);
        i = j + 1;
        continue;
      }
      if (c <= 32 || c === 61 || isTagNameChar(c)) {
        i++;
        continue;
      }
      return fail(i);
    }
    for (;;) {
      if (i >= n) return fail(n);
      const c = raw.charCodeAt(i);
      if (c === 123) {
        const e = lexCode(i + 1, true);
        if (e >= n) return fail(n);
        i = e + 1;
        continue;
      }
      if (c === 60) {
        const d = raw.charCodeAt(i + 1);
        if (d === 47) {
          const j = raw.indexOf(">", i + 2);
          return j < 0 ? fail(n) : j + 1;
        }
        if (isIdStart(d) || d === 62) {
          const e = lexJsx(i);
          if (e >= 0) {
            i = e;
            continue;
          }
          restore(i, failPos);
        }
      }
      if (c !== 10 && c !== 13) bare[i] = 32;
      i++;
    }
  };

  const tryJsx = (start: number): number => {
    const e = lexJsx(start);
    if (e >= 0) return e;
    restore(start, failPos);
    return -1;
  };

  /** Lexes code from `start`. When `nested`, stops at (and returns the index of) the unmatched `}`. */
  function lexCode(start: number, nested: boolean): number {
    let i = start;
    let depth = 0;
    let regexOk = true;
    while (i < n) {
      const c = raw.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13 || c === 0xa0 || c === 0xfeff) {
        i++;
        continue;
      }
      if (c === 47) {
        const d = raw.charCodeAt(i + 1);
        if (d === 47) {
          i = lineComment(i);
          continue;
        }
        if (d === 42) {
          i = blockComment(i);
          continue;
        }
        if (regexOk && d !== 62) {
          const e = scanRegex(i);
          if (e > 0) {
            i = e;
            regexOk = false;
            continue;
          }
        }
        i++;
        regexOk = true;
        continue;
      }
      if (c === 34 || c === 39) {
        i = skipString(i, c);
        regexOk = false;
        continue;
      }
      if (c === 96) {
        i = lexTemplate(i);
        regexOk = false;
        continue;
      }
      if (isIdStart(c)) {
        const s = i;
        i++;
        while (i < n && isIdPart(raw.charCodeAt(i))) i++;
        const len = i - s;
        regexOk = len >= 2 && len <= 10 && (s === 0 || raw.charCodeAt(s - 1) !== 46) && REGEX_KEYWORDS.has(raw.slice(s, i));
        continue;
      }
      if (c >= 48 && c <= 57) {
        i++;
        while (i < n) {
          const d = raw.charCodeAt(i);
          if (!isIdPart(d) && d !== 46) break;
          i++;
        }
        regexOk = false;
        continue;
      }
      switch (c) {
        case 123:
          depth++;
          regexOk = true;
          i++;
          break;
        case 125:
          if (depth === 0 && nested) return i;
          if (depth > 0) depth--;
          regexOk = true;
          i++;
          break;
        case 41:
        case 93:
          regexOk = false;
          i++;
          break;
        case 43:
        case 45:
          regexOk = raw.charCodeAt(i - 1) !== c;
          i++;
          break;
        case 60: {
          if (jsx && regexOk) {
            const nx = raw.charCodeAt(i + 1);
            if (isIdStart(nx) || nx === 62) {
              const e = tryJsx(i);
              if (e > 0) {
                i = e;
                regexOk = false;
                break;
              }
            }
          }
          regexOk = true;
          i++;
          break;
        }
        default:
          regexOk = true;
          i++;
      }
    }
    return n;
  }

  if (raw.startsWith("#!")) {
    const e = lineComment(0);
    lexCode(e, false);
  } else {
    lexCode(0, false);
  }

  const lineStarts: number[] = [0];
  for (let p = raw.indexOf("\n"); p >= 0; p = raw.indexOf("\n", p + 1)) lineStarts.push(p + 1);

  return { path, raw, code: toText(code), bare: toText(bare), lineStarts };
}
