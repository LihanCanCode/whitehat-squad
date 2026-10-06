import type { ReviewUnit } from "./surface.js";

export interface Quote {
  readonly file: string;
  readonly line: number;
  readonly quote: string;
}

const LINE = /^\s*(\d+) \| (.*)$/;
const SQL_HEADER = /^-- (.+\.sql)$/i;
const TOLERANCE = 2;
/** A partial quote must be distinctive; shorter text only counts when it is the whole line. */
const MIN_PARTIAL = 12;
const MIN_WHOLE = 4;

const norm = (s: string): string => s.replace(/\r/g, "").replace(/\s+/g, " ").trim();

/** file -> line -> text, from the exact line-numbered excerpts the model was shown. */
export function shownLines(u: ReviewUnit): Map<string, Map<number, string>> {
  const out = new Map<string, Map<number, string>>();
  const add = (file: string, excerpt: string): void => {
    const lines = out.get(file) ?? new Map<number, string>();
    for (const l of excerpt.split("\n")) {
      const m = LINE.exec(l);
      if (m?.[1]) lines.set(Number(m[1]), m[2] ?? "");
    }
    out.set(file, lines);
  };
  if (u.kind === "sql") {
    // One excerpt holds several files, each introduced by "-- <path>".
    let current = u.file;
    let block: string[] = [];
    for (const l of u.excerpt.split("\n")) {
      const header = SQL_HEADER.exec(l);
      if (header?.[1]) {
        add(current, block.join("\n"));
        current = header[1];
        block = [];
      } else block.push(l);
    }
    add(current, block.join("\n"));
  } else {
    add(u.file, u.excerpt);
  }
  for (const r of u.related) add(r.file, r.excerpt);
  return out;
}

function lineMatches(have: string | undefined, want: string): boolean {
  if (have === undefined) return false;
  const h = norm(have);
  if (h === want) return want.length >= MIN_WHOLE;
  return want.length >= MIN_PARTIAL && h.includes(want);
}

/**
 * The real line a quote refers to (cited line ±2), or undefined when the text was not shown there.
 * Multi-line quotes must match consecutive lines. Rejects invented code, wrong files and generic
 * fragments such as "return" that would match almost anywhere.
 */
export function matchQuote(q: Quote, shown: Map<string, Map<number, string>>): number | undefined {
  const lines = shown.get(q.file);
  if (!lines) return undefined;
  const parts = q.quote.split(/\r?\n/).map(norm).filter((p) => p.length > 0);
  if (parts.length === 0) return undefined;
  for (let start = q.line - TOLERANCE; start <= q.line + TOLERANCE; start++) {
    if (parts.every((p, i) => lineMatches(lines.get(start + i), p))) return start;
  }
  return undefined;
}

export function quoteIsReal(q: Quote, shown: Map<string, Map<number, string>>): boolean {
  return matchQuote(q, shown) !== undefined;
}

/**
 * Every cited line must be real; one invented quote discredits the whole candidate. Returns the
 * evidence with each line corrected to where the quote actually is, or undefined.
 */
export function verifyQuotes(evidence: readonly Quote[], shown: Map<string, Map<number, string>>): Quote[] | undefined {
  if (evidence.length === 0) return undefined;
  const out: Quote[] = [];
  for (const q of evidence) {
    const line = matchQuote(q, shown);
    if (line === undefined) return undefined;
    out.push({ ...q, line });
  }
  return out;
}

export function allQuotesReal(evidence: readonly Quote[], shown: Map<string, Map<number, string>>): boolean {
  return verifyQuotes(evidence, shown) !== undefined;
}
