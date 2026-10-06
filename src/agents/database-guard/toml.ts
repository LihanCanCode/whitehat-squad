/**
 * Minimal, tolerant TOML reader for supabase/config.toml. Not a validator: it understands sections
 * (including dotted and quoted names), `key = value` with strings / booleans / numbers, skips arrays and
 * inline tables, and never throws.
 */

export type TomlValue = string | number | boolean;

export interface TomlSection {
  /** 1-based line of the `[section]` header (0 for the root section). */
  readonly line: number;
  readonly values: Record<string, TomlValue>;
  /** 1-based line of each key. */
  readonly lines: Record<string, number>;
}

const MAX_LINES = 20000;

/** Removes a trailing `# comment`, respecting quotes. */
function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

/** Splits a dotted key / section name on dots outside quotes, unquoting each part. */
function splitDotted(raw: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (const c of raw.trim()) {
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === ".") {
      parts.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  parts.push(cur.trim());
  return parts;
}

function unescapeBasic(s: string): string {
  return s.replace(/\\(["\\ntr])/g, (_m, c: string) => (c === "n" ? "\n" : c === "t" ? "\t" : c === "r" ? "\r" : c));
}

function parseValue(raw: string): TomlValue | undefined {
  const v = raw.trim();
  if (v === "") return undefined;
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) return unescapeBasic(v.slice(1, -1));
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) return v.slice(1, -1);
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^[+-]?\d[\d_]*(\.\d+)?$/.test(v)) return Number(v.replace(/_/g, ""));
  if (v.startsWith("[") || v.startsWith("{")) return undefined;
  return v;
}

function bracketBalance(s: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (const c of s) {
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
  }
  return depth;
}

export function parseToml(text: string): Map<string, TomlSection> {
  const sections = new Map<string, { line: number; values: Record<string, TomlValue>; lines: Record<string, number> }>();
  const open = (name: string, line: number) => {
    let s = sections.get(name);
    if (!s) {
      s = { line, values: {}, lines: {} };
      sections.set(name, s);
    }
    return s;
  };
  let current = open("", 0);
  const lines = text.split(/\r?\n/).slice(0, MAX_LINES);
  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i] ?? "").trim();
    if (!line) continue;
    const header = /^\[\[?\s*([^\]]+?)\s*\]\]?$/.exec(line);
    if (header?.[1]) {
      current = open(splitDotted(header[1]).join("."), i + 1);
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = splitDotted(line.slice(0, eq)).join(".");
    let value = line.slice(eq + 1).trim();
    if (value.startsWith('"""') || value.startsWith("'''")) {
      const q = value.slice(0, 3);
      let j = i;
      while (!(value.length > 3 && value.endsWith(q)) && j + 1 < lines.length) value += `\n${lines[++j] ?? ""}`;
      i = j;
      continue;
    }
    const keyLine = i + 1;
    let balance = bracketBalance(value);
    let j = i;
    while (balance > 0 && j + 1 < lines.length && j - i < 500) {
      value += ` ${stripComment(lines[++j] ?? "").trim()}`;
      balance = bracketBalance(value);
    }
    i = j;
    const parsed = parseValue(value);
    if (key && parsed !== undefined) {
      current.values[key] = parsed;
      current.lines[key] = keyLine;
    }
  }
  return sections;
}
