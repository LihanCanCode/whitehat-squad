import type { ScanContext } from "../../core/types.js";

const SENSITIVE_COL =
  /^(?:role|roles|is_?admin|is_?super_?user|is_?staff|credits?|balance|plan|tier|is_?premium|is_?pro|permissions?|stripe_?customer_?id|subscription_?\w*)$/i;

const PRISMA_MODEL = /\bmodel\s+(\w+)\s*\{([^}]*)\}/g;
const SQL_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?\w+"?\.)?"?(\w+)"?\s*\(([\s\S]*?)\)\s*;/gi;
const DRIZZLE_TABLE = /(?:export\s+const\s+(\w+)\s*=\s*)?(?:pg|mysql|sqlite)Table\(\s*["'](\w+)["']\s*,\s*\{([\s\S]*?)\}\s*[,)]/g;
const MONGOOSE_SCHEMA = /(?:const|let)\s+(\w+?)(?:Schema)\s*=\s*new\s+(?:mongoose\.)?Schema\(\s*\{([\s\S]*?)\}\s*[,)]/g;
const MAX_CONFIG_BYTES = 400_000;

/** Normalised model/table key: lower case, no underscores, no plural "s". */
export function targetKey(name: string): string {
  return name.toLowerCase().replace(/[_\-"`]/g, "").replace(/s$/, "");
}

function hasSensitiveColumn(body: string): boolean {
  return body.split(/[\n,]/).some((line) => {
    const m = /^\s*"?`?([A-Za-z_]\w*)/.exec(line.replace(/^\s*(?:\/\/.*)?/, ""));
    return m?.[1] !== undefined && SENSITIVE_COL.test(m[1]);
  });
}

/** Names of models/tables (Prisma, SQL, Drizzle, Mongoose) that have role/admin/credit-like columns. */
export function sensitiveTargetsIn(text: string): string[] {
  const out: string[] = [];
  const add = (names: Array<string | undefined>, body: string): void => {
    if (!hasSensitiveColumn(body)) return;
    for (const n of names) if (n) out.push(targetKey(n));
  };
  for (const m of text.matchAll(PRISMA_MODEL)) add([m[1]], m[2] ?? "");
  for (const m of text.matchAll(SQL_TABLE)) add([m[1]], m[2] ?? "");
  for (const m of text.matchAll(DRIZZLE_TABLE)) add([m[1], m[2]], m[3] ?? "");
  for (const m of text.matchAll(MONGOOSE_SCHEMA)) add([m[1]], m[2] ?? "");
  return out;
}

export async function loadSensitiveTargets(ctx: ScanContext): Promise<Set<string>> {
  const found = new Set<string>();
  for (const path of ctx.files.paths) {
    if (!/\.(?:prisma|sql|ts|js|mjs)$/.test(path)) continue;
    if (/(?:^|\/)node_modules\//.test(path)) continue;
    if (!/(?:schema|model|migration|db|drizzle|supabase|prisma|\.sql$)/i.test(path)) continue;
    const text = await ctx.files.read(path);
    if (text === null || text.length > MAX_CONFIG_BYTES) continue;
    for (const t of sensitiveTargetsIn(text)) found.add(t);
  }
  return found;
}
