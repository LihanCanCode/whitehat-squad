/** Finds which `match /path { ... }` blocks enclose a position in a Firestore / Storage rules file. */

interface Block {
  readonly start: number;
  readonly end: number;
  readonly path: string;
}

const MATCH = /\bmatch\s+((?:[^{}\s]|\{[^{}]*\})+)\s*\{/g;
const MAX_BLOCKS = 2000;

function closeOf(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return i;
  }
  return src.length;
}

/** Returns a function mapping a source offset to the concatenated path of its enclosing match blocks. */
export function enclosingMatchPaths(clean: string): (index: number) => string {
  const blocks: Block[] = [];
  let m: RegExpExecArray | null;
  MATCH.lastIndex = 0;
  while ((m = MATCH.exec(clean)) && blocks.length < MAX_BLOCKS) {
    const open = m.index + m[0].length - 1;
    blocks.push({ start: open, end: closeOf(clean, open), path: m[1] ?? "" });
  }
  return (index) => blocks.filter((b) => b.start < index && index < b.end).map((b) => b.path).join("");
}

/**
 * True when the path covers many documents/files: a recursive `{x=**}` wildcard, or a first segment that is
 * itself a variable (`/{collection}/{doc}`). The `/databases/{db}/documents` and `/b/{bucket}/o` prefixes are ignored.
 */
export function isWildcardPath(joined: string): boolean {
  const normalized = joined.replace(/^\/?databases\/\{[^}]*\}\/documents/, "").replace(/^\/?b\/\{[^}]*\}\/o/, "");
  const segments = normalized.split("/").filter(Boolean);
  if (segments.length === 0) return false;
  return /=\s*\*\*/.test(normalized) || /^\{[^}]+\}$/.test(segments[0] as string);
}
