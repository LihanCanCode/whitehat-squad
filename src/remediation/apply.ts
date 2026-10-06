import { promises as fs } from "node:fs";
import path from "node:path";
import type { RemediationPlan, ScanReport } from "../core/types.js";
import { assertSafeTarget } from "../safety/safe-write.js";
import { renderPlanDocument } from "./render.js";

export const GITIGNORE_LINES: readonly string[] = [".env", ".env.*", "!.env.example"];
export const MIGRATION_SUFFIX = "_whsquad_security_fixes.sql";
export const PLAN_FILE = ".whsquad/fix-plan.md";

export interface ApplyResult {
  /** What was written or changed, one line each, relative to the project root. */
  readonly changed: readonly string[];
  /** What was deliberately left alone, and why. */
  readonly skipped: readonly string[];
}

interface Outcome {
  readonly changed?: string;
  readonly skipped?: string;
}

/** UTC timestamp in Supabase migration form: YYYYMMDDHHMMSS. */
export function migrationTimestamp(date: Date): string {
  return date.toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

async function readIfExists(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

/** Appends the missing env-file lines. Never removes or reorders existing lines. */
async function updateGitignore(root: string): Promise<Outcome> {
  const file = path.join(root, ".gitignore");
  await assertSafeTarget(root, file);
  const current = await readIfExists(file);
  const present = new Set((current ?? "").split(/\r?\n/).map((l) => l.trim()));
  const missing = GITIGNORE_LINES.filter((l) => !present.has(l));
  if (missing.length === 0) return { skipped: ".gitignore already ignores .env files" };
  const eol = current?.includes("\r\n") ? "\r\n" : "\n";
  const separator = current === null || current === "" || current.endsWith("\n") ? "" : eol;
  const addition = `${separator}${["# added by whsquad fix", ...missing].join(eol)}${eol}`;
  await fs.writeFile(file, (current ?? "") + addition, "utf8");
  return { changed: `.gitignore: appended ${missing.join(", ")}` };
}

async function isDirectory(p: string): Promise<boolean> {
  return (await fs.stat(p).catch(() => null))?.isDirectory() ?? false;
}

/** Writes ONE new migration, unless the repo has no supabase/ dir or an identical one already exists. */
async function writeMigration(root: string, sql: string, now: Date): Promise<Outcome> {
  const supabase = path.join(root, "supabase");
  await assertSafeTarget(root, path.join(supabase, "migrations", "x.sql"));
  if (!(await isDirectory(supabase))) {
    return { skipped: "no supabase/ directory, so the SQL migration was not written (it is in the plan)" };
  }
  const dir = path.join(supabase, "migrations");
  const existing = (await fs.readdir(dir).catch(() => [] as string[])).filter((f) => f.endsWith(MIGRATION_SUFFIX));
  for (const name of existing) {
    if ((await readIfExists(path.join(dir, name))) === sql) {
      return { skipped: `supabase/migrations/${name} already contains this migration` };
    }
  }
  const name = `${migrationTimestamp(now)}${MIGRATION_SUFFIX}`;
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.writeFile(path.join(dir, name), sql, { encoding: "utf8", flag: "wx" });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return { skipped: `supabase/migrations/${name} already exists; not overwritten` };
    throw e;
  }
  return { changed: `supabase/migrations/${name}: new migration with the merged SQL fixes` };
}

async function writePlanFile(root: string, plan: RemediationPlan, target: string): Promise<Outcome> {
  const file = path.join(root, ...PLAN_FILE.split("/"));
  const doc = renderPlanDocument(plan, target) + "\n";
  await assertSafeTarget(root, file);
  if ((await readIfExists(file)) === doc) return { skipped: `${PLAN_FILE} is already up to date` };
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, doc, "utf8");
  return { changed: `${PLAN_FILE}: the fix plan` };
}

/**
 * Applies ONLY safe, additive, deterministic changes: append to .gitignore, add one new migration
 * file, write .whsquad/fix-plan.md. Never edits existing source, never runs a package manager or git.
 */
export async function applyFixes(
  report: ScanReport,
  plan: RemediationPlan,
  root: string,
  now: () => Date = () => new Date(),
): Promise<ApplyResult> {
  // Check every target before the first write, so a refusal leaves the repo untouched.
  for (const target of [".gitignore", "supabase/migrations/x.sql", PLAN_FILE]) {
    await assertSafeTarget(root, path.join(root, ...target.split("/")));
  }
  const outcomes: Outcome[] = [];
  if (report.findings.some((f) => f.ruleId === "SEC-100")) outcomes.push(await updateGitignore(root));
  if (plan.migrationSql) outcomes.push(await writeMigration(root, plan.migrationSql, now()));
  outcomes.push(await writePlanFile(root, plan, report.target));
  return {
    changed: outcomes.flatMap((o) => (o.changed ? [o.changed] : [])),
    skipped: outcomes.flatMap((o) => (o.skipped ? [o.skipped] : [])),
  };
}
