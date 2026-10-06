/** Tolerant SQL statement splitter. Not a parser: it never throws and never rejects input. */

export interface SqlStatement {
  /** Statement with comments removed (strings and dollar bodies kept). */
  readonly text: string;
  /** Like text, but string literals and dollar-quoted bodies are blanked. Used for structural matching. */
  readonly skeleton: string;
  /** 1-based line of the first significant character. */
  readonly line: number;
}

const IDENT_CHAR = /[A-Za-z0-9_$]/;
const DOLLAR_TAG = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;

/** Regex source for one (possibly quoted) identifier. */
export const ID = '(?:"(?:[^"]|"")+"|[A-Za-z_][\\w$]*)';
/** Regex source for an optionally schema-qualified name; captures (schema|name, name?). */
export const QN = `(${ID})(?:\\s*\\.\\s*(${ID}))?`;

export function unquoteIdent(raw: string): string {
  const t = raw.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) return t.slice(1, -1).replace(/""/g, '"').toLowerCase();
  return t.toLowerCase();
}

/** Skips a quoted run starting at `start` (opening quote). Returns the index after the closing quote. */
function skipQuoted(s: string, start: number, backslash: boolean): number {
  const q = s[start];
  let i = start + 1;
  while (i < s.length) {
    const c = s[i];
    if (backslash && c === "\\") {
      i += 2;
      continue;
    }
    if (c === q) {
      if (s[i + 1] === q) {
        i += 2;
        continue;
      }
      return i + 1;
    }
    i++;
  }
  return s.length;
}

export function splitStatements(sql: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  let text = "";
  let skel = "";
  let line = 1;
  let startLine = 0;
  let i = 0;

  const push = (): void => {
    const t = text.trim();
    if (t) out.push({ text: t, skeleton: skel.trim(), line: startLine || 1 });
    text = "";
    skel = "";
    startLine = 0;
  };
  const countLines = (chunk: string): number => {
    let n = 0;
    for (let k = 0; k < chunk.length; k++) if (chunk.charCodeAt(k) === 10) n++;
    return n;
  };
  const add = (t: string, k: string): void => {
    if (!startLine && t.trim()) startLine = line;
    text += t;
    skel += k;
    line += countLines(t);
  };

  while (i < sql.length) {
    const c = sql[i] as string;
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      let end = sql.indexOf("\n", i);
      if (end === -1) end = sql.length;
      i = end;
      continue;
    }
    if (c === "/" && next === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === "/" && sql[j + 1] === "*") { depth++; j += 2; }
        else if (sql[j] === "*" && sql[j + 1] === "/") { depth--; j += 2; }
        else j++;
      }
      const chunk = sql.slice(i, j);
      line += countLines(chunk);
      text += " ";
      skel += " ";
      i = j;
      continue;
    }
    if (c === "'") {
      const escaped = /[eE]/.test(sql[i - 1] ?? "") && !IDENT_CHAR.test(sql[i - 2] ?? " ");
      const end = skipQuoted(sql, i, escaped);
      add(sql.slice(i, end), "''");
      i = end;
      continue;
    }
    if (c === '"') {
      const end = skipQuoted(sql, i, false);
      const chunk = sql.slice(i, end);
      add(chunk, chunk);
      i = end;
      continue;
    }
    if (c === "$" && !IDENT_CHAR.test(sql[i - 1] ?? " ")) {
      const m = DOLLAR_TAG.exec(sql.slice(i, i + 64));
      if (m) {
        const tag = m[0];
        const close = sql.indexOf(tag, i + tag.length);
        const end = close === -1 ? sql.length : close + tag.length;
        add(sql.slice(i, end), `${tag}${tag}`);
        i = end;
        continue;
      }
    }
    if (c === ";") {
      push();
      i++;
      continue;
    }
    add(c, c);
    i++;
  }
  push();
  return out;
}

/** Inner text of the parenthesis group opening at `openIdx` (must point at "("). Null if unbalanced. */
export function balancedInner(s: string, openIdx: number): string | null {
  if (s[openIdx] !== "(") return null;
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i];
    if (c === "'" || c === '"') {
      i = skipQuoted(s, i, false) - 1;
    } else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return s.slice(openIdx + 1, i);
  }
  return null;
}

/** Splits on `sep` ignoring separators inside parens and quotes. */
export function splitTopLevel(s: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" || c === '"') {
      i = skipQuoted(s, i, false) - 1;
    } else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === sep && depth === 0) {
      parts.push(s.slice(last, i).trim());
      last = i + 1;
    }
  }
  const tail = s.slice(last).trim();
  if (tail || parts.length > 0) parts.push(tail);
  return parts;
}

/** Inner text of each top-level parenthesis group, e.g. a VALUES list. */
export function parenGroups(s: string): string[] {
  const groups: string[] = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"') {
      i = skipQuoted(s, i, false);
    } else if (c === "(") {
      const inner = balancedInner(s, i);
      if (inner === null) break;
      groups.push(inner);
      i += inner.length + 2;
    } else i++;
  }
  return groups;
}
