import type { FileIndex, Finding, SuppressedFinding } from "./types.js";

export interface IgnoreDirective {
  /** Upper-cased rule ids or prefix wildcards such as "DB-*". */
  readonly rules: readonly string[];
  readonly reason?: string;
}

// A rule token is an id ("SEC-090") or a prefix wildcard ("DB-*", "SEC-0*").
const RULE_TOKEN = "[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9]*\\*?";
const DIRECTIVE = new RegExp(
  `whsquad-ignore(?![\\w-])\\s+(${RULE_TOKEN}(?:\\s*,\\s*${RULE_TOKEN})*)(?:\\s+--(?=\\s|$)\\s*(.*))?`,
);
// The directive only counts inside a comment: //, #, --, /* ... */, <!-- ... -->, or a block-comment " * " line.
const COMMENT_OPENER = /\/\/|#|--|\/\*|<!--|^\s*\*/;
const COMMENT_CLOSER = /\s*(?:\*\/|-->)\s*$/;

/** Parses `whsquad-ignore RULE[,RULE...] [-- reason]` from one source line, or null. */
export function parseIgnoreDirective(line: string): IgnoreDirective | null {
  const start = line.indexOf("whsquad-ignore");
  if (start < 0 || !COMMENT_OPENER.test(line.slice(0, start))) return null;
  const m = DIRECTIVE.exec(line.slice(start));
  if (!m) return null;
  const rules = (m[1] as string).split(",").map((t) => t.trim().toUpperCase());
  const reason = (m[2] ?? "").replace(COMMENT_CLOSER, "").trim();
  return reason ? { rules, reason } : { rules };
}

/** Exact id, or a prefix wildcard when the pattern ends in "*". */
export function matchesRule(pattern: string, ruleId: string): boolean {
  const p = pattern.toUpperCase();
  const id = ruleId.toUpperCase();
  return p.endsWith("*") ? id.startsWith(p.slice(0, -1)) : id === p;
}

export interface SuppressionResult {
  readonly kept: Finding[];
  readonly suppressed: SuppressedFinding[];
}

/**
 * Removes findings whose primary evidence line, or the line directly above it, carries a matching
 * directive. Works for every agent because it reads the file the finding points at.
 */
export async function applySuppressions(findings: readonly Finding[], files: FileIndex): Promise<SuppressionResult> {
  const lineCache = new Map<string, readonly string[] | null>();
  const linesOf = async (file: string): Promise<readonly string[] | null> => {
    if (!lineCache.has(file)) {
      const text = await files.read(file);
      lineCache.set(file, text === null ? null : text.split(/\r?\n/));
    }
    return lineCache.get(file) ?? null;
  };

  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const ev = f.evidence.find((e) => e.file && e.line && e.line > 0);
    const lines = ev?.file ? await linesOf(ev.file) : null;
    const hit = ev?.line && lines ? findDirective(lines, ev.line, f.ruleId) : null;
    if (!hit || !ev) {
      kept.push(f);
      continue;
    }
    suppressed.push({
      id: f.id,
      ruleId: f.ruleId,
      ...(ev.file ? { file: ev.file } : {}),
      ...(ev.line ? { line: ev.line } : {}),
      ...(hit.reason ? { reason: hit.reason } : {}),
    });
  }
  return { kept, suppressed };
}

function findDirective(lines: readonly string[], line: number, ruleId: string): IgnoreDirective | null {
  for (const candidate of [lines[line - 1], lines[line - 2]]) {
    if (candidate === undefined) continue;
    const d = parseIgnoreDirective(candidate);
    if (d?.rules.some((r) => matchesRule(r, ruleId))) return d;
  }
  return null;
}
