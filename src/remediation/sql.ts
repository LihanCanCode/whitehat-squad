/** Splits a SQL block into statements at lines ending in ";". Blocks with dollar-quoting are never split. */
function statementsOf(block: string): string[] {
  if (block.includes("$")) return [block];
  const out: string[] = [];
  let current: string[] = [];
  for (const line of block.split("\n")) {
    current.push(line);
    const t = line.trim();
    if (t.endsWith(";") && !t.startsWith("--")) {
      out.push(current.join("\n"));
      current = [];
    }
  }
  if (current.join("").trim() !== "") out.push(current.join("\n"));
  return out;
}

export interface SqlSource {
  readonly stepId: string;
  readonly title: string;
  readonly sql: string;
}

/** Returns the statements of `sql` not yet in `seen`, and records them. */
function freshStatements(sql: string, seen: Set<string>): string[] {
  const fresh: string[] = [];
  for (const stmt of statementsOf(sql.trim())) {
    const key = stmt.trim();
    if (key === "" || seen.has(key)) continue;
    seen.add(key);
    fresh.push(key);
  }
  return fresh;
}

/** Concatenates fix SQL in order, dropping statements that were already emitted. */
export function dedupeSql(sqls: readonly string[]): string {
  const seen = new Set<string>();
  return sqls.flatMap((sql) => freshStatements(sql, seen)).join("\n");
}

/** One migration: header comment listing the finding ids, then each step's deduplicated SQL. */
export function buildMigration(sources: readonly SqlSource[], findingIds: readonly string[]): string | undefined {
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const s of sources) {
    const fresh = freshStatements(s.sql, seen);
    if (fresh.length > 0) parts.push(`-- ${s.stepId}: ${s.title}\n${fresh.join("\n")}`);
  }
  if (parts.length === 0) return undefined;
  const header = [
    "-- whitehat-squad security fixes (generated; review before applying)",
    `-- Addresses findings: ${findingIds.join(", ")}`,
    "-- Test on a branch or staging database first. Never edit an already-applied migration.",
  ].join("\n");
  return `${header}\n\n${parts.join("\n\n")}\n`;
}
