/** Text-level helpers for binding patterns and parameter lists (`{ a, b: { c }, ...rest }`, `[x, , y = 1]`). */

const IDENT = /^[A-Za-z_$][\w$]*$/;

function skipQuoted(text: string, i: number): number {
  const q = text.charAt(i);
  let j = i + 1;
  while (j < text.length) {
    const c = text.charAt(j);
    if (c === "\\") j += 2;
    else if (c === q) return j;
    else j++;
  }
  return text.length;
}

/** Splits at top-level `sep` (depth over `()[]{}` and type angle brackets; quotes skipped). */
export function splitTopLevel(text: string, sep = ","): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === "`") {
      i = skipQuoted(text, i);
    } else if (c === "(" || c === "[" || c === "{" || c === "<") {
      depth++;
    } else if (c === ")" || c === "]" || c === "}" || (c === ">" && text.charAt(i - 1) !== "=")) {
      depth = Math.max(0, depth - 1);
    } else if (c === sep && depth === 0) {
      out.push(text.slice(start, i));
      start = i + 1;
    }
  }
  out.push(text.slice(start));
  return out;
}

/** Index of the first `ch` outside any bracket (angle brackets ignored), or -1. */
export function findTopLevel(text: string, ch: string): number {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === "`") i = skipQuoted(text, i);
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth = Math.max(0, depth - 1);
    else if (c === ch && depth === 0) return i;
  }
  return -1;
}

/** Index of a top-level assignment `=` (not `==`, `=>`, `<=`, `>=`, `!=`), or -1. */
function findAssign(text: string): number {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === "`") i = skipQuoted(text, i);
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth = Math.max(0, depth - 1);
    else if (c === "=" && depth === 0) {
      const prev = text.charAt(i - 1);
      const next = text.charAt(i + 1);
      if (next === "=" || next === ">" || prev === "<" || prev === ">" || prev === "!" || prev === "=") continue;
      return i;
    }
  }
  return -1;
}

function closerIndex(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === "`") i = skipQuoted(text, i);
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Names bound by a pattern: handles nesting, `a: renamed`, defaults, rest and array holes. Trailing type
 * annotations (`{ a }: Props`) are ignored.
 */
export function parseBindingNames(pattern: string): string[] {
  const t = pattern.trim();
  if (t === "") return [];
  const first = t.charAt(0);
  if (first === "{" || first === "[") {
    const close = closerIndex(t, 0);
    const inner = t.slice(1, close < 0 ? t.length : close);
    const out: string[] = [];
    for (const el of splitTopLevel(inner)) {
      let e = el.trim();
      if (e === "") continue;
      if (e.startsWith("...")) {
        out.push(...parseBindingNames(e.slice(3)));
        continue;
      }
      const eq = findAssign(e);
      if (eq >= 0) e = e.slice(0, eq);
      if (first === "{") {
        const colon = findTopLevel(e, ":");
        if (colon >= 0) e = e.slice(colon + 1);
      }
      out.push(...parseBindingNames(e));
    }
    return out;
  }
  const m = /^([A-Za-z_$][\w$]*)/.exec(t);
  return m?.[1] ? [m[1]] : [];
}

export interface ParamInfo {
  readonly text: string;
  readonly names: readonly string[];
  readonly destructured: boolean;
}

const MODIFIERS = /^(?:(?:public|private|protected|readonly|override)\s+)+/;

/** Parses a parameter list (the text between the parentheses) into per-parameter info. */
export function parseParams(params: string): ParamInfo[] {
  const out: ParamInfo[] = [];
  for (const raw of splitTopLevel(params)) {
    let text = raw.trim().replace(/^@\w+(?:\([^)]*\))?\s*/, "").replace(MODIFIERS, "");
    if (text === "" || text.startsWith("this:")) continue;
    if (text.startsWith("...")) text = text.slice(3);
    const destructured = text.startsWith("{") || text.startsWith("[");
    out.push({ text, names: parseBindingNames(text), destructured });
  }
  return out;
}

export const isIdentifier = (s: string): boolean => IDENT.test(s);
