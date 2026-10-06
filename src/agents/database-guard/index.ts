import type { Agent, Finding, ScanContext } from "../../core/types.js";
import { analyzeFirebaseRules, firebaseKind } from "./firebase-rules.js";
import type { FirebaseKind } from "./firebase-rules.js";
import { runLiveProbes } from "./live.js";
import { buildModel } from "./sql-model.js";
import { analyzeSql } from "./sql-rules.js";
import { addConfigBuckets, analyzeConfig, loadConfigs } from "./supabase-config.js";

const SQL_FILE = /\.sql$/i;
/** Directories whose .sql files are treated as the database schema, at any depth. */
const SQL_DIRS = /(^|\/)(supabase|prisma\/migrations|drizzle|migrations|db\/migrations|sql|database)\//;

export function isSqlPath(p: string): boolean {
  if (!SQL_FILE.test(p) || p.includes("node_modules/")) return false;
  return SQL_DIRS.test(p) || /(^|\/)schema\.sql$/i.test(p) || /(^|\/)db\/[^/]+\.sql$/i.test(p);
}

/** SQL comments blanked so a word in `-- unsigned urls` can never decide the dialect. */
const stripSqlComments = (s: string): string => s.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");

const MYSQL_MARKER = /\bENGINE\s*=\s*InnoDB\b|\bAUTO_INCREMENT\b|\bSET\s+FOREIGN_KEY_CHECKS\b|^[ \t]*DELIMITER[ \t]+\S|\bON\s+UPDATE\s+CURRENT_TIMESTAMP\b/im;
const POSTGRES_MARKER =
  /\bROW\s+LEVEL\s+SECURITY\b|\bCREATE\s+POLICY\b|\bauth\.(?:uid|jwt|role)\s*\(|\bLANGUAGE\s+plpgsql\b|\bAS\s+\$\w*\$|\bSERIAL\b|\bTIMESTAMPTZ\b|\bJSONB\b|\bgen_random_uuid\s*\(/i;
const SUPABASE_SQL =
  /\bauth\.(?:uid|jwt|role)\s*\(|\bauth\.users\b|\bstorage\.(?:objects|buckets)\b|\bto\s+(?:anon|authenticated|service_role)\b|\bROW\s+LEVEL\s+SECURITY\b|\bCREATE\s+POLICY\b/i;
const SUPABASE_PATH = /(^|\/)supabase\//;

/**
 * MySQL / MariaDB / TiDB schemas have no Row Level Security or PostgREST: every RLS rule would be a
 * false positive. True only when some file is clearly MySQL and nothing anywhere is Postgres.
 */
export function isMysqlOnly(sql: readonly { content: string }[]): boolean {
  const bodies = sql.map((f) => stripSqlComments(f.content));
  return bodies.some((b) => MYSQL_MARKER.test(b)) && !bodies.some((b) => POSTGRES_MARKER.test(b));
}

/** Dependency manifests in any ecosystem (Supabase ships clients for JS, Python, Dart, Swift, Kotlin...). */
const MANIFEST =
  /(?:^|\/)(?:package\.json|requirements[\w.-]*\.txt|pyproject\.toml|Pipfile|pubspec\.yaml|deno\.jsonc?|import_map\.json|Package\.swift|build\.gradle(?:\.kts)?|go\.mod|Gemfile|composer\.json)$/;
const ENV_FILE = /(?:^|\/)\.env(?:\.[\w-]+)?$/;
const SUPABASE_ENV = /^[ \t]*(?:export[ \t]+)?(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|PUBLIC_|REACT_APP_)?SUPABASE_\w+[ \t]*=/m;
/** Server-only database access: these talk to Postgres/MySQL directly, never through PostgREST. */
const SERVER_DB =
  /(?:^|["'\s])(?:drizzle-orm|prisma|@prisma\/client|pg|postgres|@neondatabase\/serverless|@vercel\/postgres|kysely|knex|sequelize|typeorm|mysql2?|@planetscale\/database|sqlalchemy|psycopg2?(?:-binary)?|asyncpg|django)(?:$|["'\s=<>~^[])/im;

interface ProjectDb {
  readonly supabase: boolean;
  readonly serverDb: boolean;
}

async function projectDb(ctx: ScanContext): Promise<ProjectDb> {
  let supabase = ctx.stack.backends.includes("supabase");
  let serverDb = false;
  for (const p of ctx.files.paths) {
    if (p.includes("node_modules/")) continue;
    const manifest = MANIFEST.test(p);
    if (!manifest && !ENV_FILE.test(p)) continue;
    const text = (await ctx.files.read(p)) ?? "";
    if (manifest) {
      supabase ||= /supabase/i.test(text);
      serverDb ||= SERVER_DB.test(text);
    } else {
      supabase ||= SUPABASE_ENV.test(text);
    }
  }
  return { supabase, serverDb };
}

/**
 * RLS rules only make sense where PostgREST exposes the public schema (Supabase). They are skipped
 * only on positive evidence that it cannot be: a MySQL schema, or a project whose sole database
 * access is a server-side driver/ORM (Drizzle, Prisma, pg on Neon...) with no Supabase mention.
 * With no evidence either way the SQL is analysed.
 */
async function sqlIsExposed(ctx: ScanContext, sql: readonly { path: string; content: string }[]): Promise<boolean> {
  if (sql.some((f) => SUPABASE_PATH.test(f.path))) return true;
  if (isMysqlOnly(sql)) return false;
  if (sql.some((f) => SUPABASE_SQL.test(stripSqlComments(f.content)))) return true;
  const db = await projectDb(ctx);
  return db.supabase || !db.serverDb;
}

/** Natural path order: digit runs compare numerically, so 2_x.sql sorts before 10_x.sql; timestamps sort as usual. */
export function naturalCompare(a: string, b: string): number {
  const pa = a.split(/(\d+)/);
  const pb = b.split(/(\d+)/);
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    const x = pa[i] as string;
    const y = pb[i] as string;
    if (x === y) continue;
    if (i % 2 === 1) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d;
      if (x.length !== y.length) return x.length - y.length;
    }
    return x < y ? -1 : 1;
  }
  return pa.length - pb.length;
}

async function readAll(ctx: ScanContext, paths: readonly string[]): Promise<{ path: string; content: string }[]> {
  const files: { path: string; content: string }[] = [];
  for (const path of [...paths].sort(naturalCompare)) {
    const content = await ctx.files.read(path);
    if (content !== null) files.push({ path, content });
  }
  return files;
}

function resolveRelative(configPath: string, rel: string): string {
  const dir = configPath.includes("/") ? configPath.slice(0, configPath.lastIndexOf("/")) : "";
  const out: string[] = [];
  for (const part of `${dir}/${rel}`.split("/")) {
    if (part === "..") out.pop();
    else if (part && part !== ".") out.push(part);
  }
  return out.join("/");
}

function declaredRules(value: unknown): string[] {
  const items = Array.isArray(value) ? value : [value];
  return items.flatMap((i) => {
    const rules = i && typeof i === "object" ? (i as { rules?: unknown }).rules : undefined;
    return typeof rules === "string" ? [rules] : [];
  });
}

/** Rules files by default name, plus any path declared in firebase.json (firestore / storage / database -> rules). */
async function firebaseRuleFiles(ctx: ScanContext): Promise<Map<string, FirebaseKind>> {
  const found = new Map<string, FirebaseKind>();
  for (const p of ctx.files.paths) {
    const kind = firebaseKind(p);
    if (kind) found.set(p, kind);
  }
  const known = new Set(ctx.files.paths);
  for (const cfg of ctx.files.paths.filter((p) => /(^|\/)firebase\.json$/.test(p)).sort()) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse((await ctx.files.read(cfg)) ?? "{}") as Record<string, unknown>;
    } catch {
      continue;
    }
    const kinds: [string, FirebaseKind][] = [["firestore", "firestore"], ["storage", "storage"], ["database", "rtdb"]];
    for (const [key, kind] of kinds) {
      for (const rel of declaredRules(parsed?.[key])) {
        const path = resolveRelative(cfg, rel);
        if (known.has(path) && !found.has(path)) found.set(path, kind);
      }
    }
  }
  return found;
}

/** Static scan. `now` is injectable for tests; the agent passes the real date. */
export async function staticScan(ctx: ScanContext, target: string, now: Date): Promise<Finding[]> {
  const findings: Finding[] = [];
  const configs = await loadConfigs(ctx);
  const allSql = await readAll(ctx, ctx.files.paths.filter(isSqlPath));
  const exposed = configs.length > 0 || (await sqlIsExposed(ctx, allSql));
  const sql = exposed ? allSql : [];
  if (sql.length > 0 || configs.length > 0) {
    const model = buildModel(sql);
    addConfigBuckets(model, configs);
    findings.push(...analyzeSql(model, target));
    findings.push(...(await analyzeConfig(ctx, configs, model, target)));
  }
  const rules = await firebaseRuleFiles(ctx);
  for (const f of await readAll(ctx, [...rules.keys()])) {
    findings.push(...analyzeFirebaseRules(f.path, f.content, target, now, rules.get(f.path)));
  }
  return findings;
}

export const agent: Agent = {
  id: "database-guard",
  name: "DatabaseGuard",
  role: "Audits Supabase RLS and Firebase rules",
  modes: ["static", "live"],
  async run(ctx) {
    const target = ctx.root ?? ctx.target?.href ?? ".";
    const findings = await staticScan(ctx, target, new Date());
    if (ctx.mode === "live") findings.push(...(await runLiveProbes(ctx, target)));
    return findings;
  },
};
