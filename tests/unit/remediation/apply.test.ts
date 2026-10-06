import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applyFixes, migrationTimestamp } from "../../../src/remediation/apply.js";
import { buildRemediationPlan } from "../../../src/remediation/plan.js";
import { makeTempDir } from "../../helpers/sample-apps.js";
import { finding, reportOf } from "./builders.js";

const CLOCK = (): Date => new Date("2026-03-04T05:06:07.890Z");
const SQL_FINDING = finding({ id: "d1", ruleId: "DB-001", sql: "ALTER TABLE t ENABLE ROW LEVEL SECURITY;", file: "a.sql", line: 1 });
const ENV_FINDING = finding({ id: "e1", ruleId: "SEC-100", file: ".env", line: 1 });

let dir: string;
beforeEach(async () => {
  dir = await makeTempDir();
});
afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

const read = (rel: string): Promise<string> => fs.readFile(path.join(dir, rel), "utf8");
const exists = (rel: string): Promise<boolean> => fs.stat(path.join(dir, rel)).then(() => true, () => false);

describe("migrationTimestamp", () => {
  it("is UTC YYYYMMDDHHMMSS", () => expect(migrationTimestamp(CLOCK())).toBe("20260304050607"));
});

describe("applyFixes: .gitignore", () => {
  it("creates .gitignore when SEC-100 fired and none exists", async () => {
    const report = reportOf([ENV_FINDING]);
    const res = await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await read(".gitignore")).toBe("# added by whsquad fix\n.env\n.env.*\n!.env.example\n");
    expect(res.changed.some((c) => c.startsWith(".gitignore"))).toBe(true);
  });

  it("appends only missing lines, never removes or reorders, and is idempotent", async () => {
    await fs.writeFile(path.join(dir, ".gitignore"), "node_modules\n.env\ndist", "utf8");
    const report = reportOf([ENV_FINDING]);
    const plan = buildRemediationPlan(report);
    await applyFixes(report, plan, dir, CLOCK);
    const once = await read(".gitignore");
    expect(once).toBe("node_modules\n.env\ndist\n# added by whsquad fix\n.env.*\n!.env.example\n");
    const second = await applyFixes(report, plan, dir, CLOCK);
    expect(await read(".gitignore")).toBe(once);
    expect(second.skipped).toContain(".gitignore already ignores .env files");
  });

  it("preserves CRLF line endings", async () => {
    await fs.writeFile(path.join(dir, ".gitignore"), "dist\r\n", "utf8");
    const report = reportOf([ENV_FINDING]);
    await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await read(".gitignore")).toBe("dist\r\n# added by whsquad fix\r\n.env\r\n.env.*\r\n!.env.example\r\n");
  });

  it("does not touch .gitignore when SEC-100 did not fire", async () => {
    const report = reportOf([SQL_FINDING]);
    await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await exists(".gitignore")).toBe(false);
  });
});

describe("applyFixes: migration", () => {
  it("writes one new migration with a UTC timestamp when supabase/ exists", async () => {
    await fs.mkdir(path.join(dir, "supabase"));
    const report = reportOf([SQL_FINDING]);
    const plan = buildRemediationPlan(report);
    const res = await applyFixes(report, plan, dir, CLOCK);
    const name = "supabase/migrations/20260304050607_whsquad_security_fixes.sql";
    expect(await read(name)).toBe(plan.migrationSql);
    expect(res.changed.some((c) => c.includes(name))).toBe(true);
  });

  it("is idempotent: an identical existing whsquad migration blocks a second write", async () => {
    await fs.mkdir(path.join(dir, "supabase"));
    const report = reportOf([SQL_FINDING]);
    const plan = buildRemediationPlan(report);
    await applyFixes(report, plan, dir, CLOCK);
    const later = await applyFixes(report, plan, dir, () => new Date("2027-01-01T00:00:00Z"));
    expect(await fs.readdir(path.join(dir, "supabase/migrations"))).toHaveLength(1);
    expect(later.skipped.some((s) => s.includes("already contains this migration"))).toBe(true);
  });

  it("writes a new file when the earlier whsquad migration has different content, and never overwrites", async () => {
    const migrations = path.join(dir, "supabase", "migrations");
    await fs.mkdir(migrations, { recursive: true });
    await fs.writeFile(path.join(migrations, "20260304050607_whsquad_security_fixes.sql"), "-- old", "utf8");
    const report = reportOf([SQL_FINDING]);
    const plan = buildRemediationPlan(report);
    const same = await applyFixes(report, plan, dir, CLOCK); // same second: wx refuses
    expect(await fs.readFile(path.join(migrations, "20260304050607_whsquad_security_fixes.sql"), "utf8")).toBe("-- old");
    expect(same.skipped.some((s) => s.includes("not overwritten"))).toBe(true);
    await applyFixes(report, plan, dir, () => new Date("2026-03-05T00:00:00Z"));
    expect(await fs.readdir(migrations)).toHaveLength(2);
  });

  it("skips the migration (but keeps it in the plan) without a supabase/ directory", async () => {
    const report = reportOf([SQL_FINDING]);
    const res = await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await exists("supabase")).toBe(false);
    expect(res.skipped.some((s) => s.includes("no supabase/ directory"))).toBe(true);
  });

  it("does not create a migration when the plan has no SQL", async () => {
    await fs.mkdir(path.join(dir, "supabase"));
    const report = reportOf([finding({ id: "a", ruleId: "AUTH-002" })]);
    await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await exists("supabase/migrations")).toBe(false);
  });
});

describe("applyFixes: fix-plan.md and boundaries", () => {
  it("writes .whsquad/fix-plan.md, and a rerun reports it as up to date", async () => {
    const report = reportOf([SQL_FINDING]);
    const plan = buildRemediationPlan(report);
    await applyFixes(report, plan, dir, CLOCK);
    const doc = await read(".whsquad/fix-plan.md");
    expect(doc).toContain("# whitehat-squad fix plan");
    expect(doc).toContain("```sql");
    expect(doc).toContain("Master prompt");
    const again = await applyFixes(report, plan, dir, CLOCK);
    expect(again.skipped).toContain(".whsquad/fix-plan.md is already up to date");
    expect(again.changed).toEqual([]);
  });

  it("never edits an existing source file", async () => {
    await fs.mkdir(path.join(dir, "src"));
    await fs.writeFile(path.join(dir, "src/a.ts"), "export const a = 1;\n", "utf8");
    const report = reportOf([finding({ id: "x", ruleId: "AUTH-002", file: "src/a.ts", line: 1 }), ENV_FINDING]);
    await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(await read("src/a.ts")).toBe("export const a = 1;\n");
    expect((await fs.readdir(dir)).sort()).toEqual([".gitignore", ".whsquad", "src"]);
  });
});

// Security review: a hostile repo must not redirect `fix --write` outside the project via links.
describe("applyFixes: refuses to write through symlinks / junctions", () => {
  let outside: string;
  beforeEach(async () => {
    outside = await makeTempDir();
  });
  afterEach(async () => {
    await fs.rm(outside, { recursive: true, force: true });
  });

  it("a .whsquad junction pointing outside the repo is refused and nothing is written there", async () => {
    await fs.symlink(outside, path.join(dir, ".whsquad"), "junction");
    const report = reportOf([SQL_FINDING]);
    await expect(applyFixes(report, buildRemediationPlan(report), dir, CLOCK)).rejects.toThrow(/symbolic link/);
    expect(await fs.readdir(outside)).toEqual([]);
  });

  it("a supabase/migrations junction is refused", async () => {
    await fs.mkdir(path.join(dir, "supabase"));
    await fs.symlink(outside, path.join(dir, "supabase", "migrations"), "junction");
    const report = reportOf([SQL_FINDING]);
    await expect(applyFixes(report, buildRemediationPlan(report), dir, CLOCK)).rejects.toThrow(/symbolic link/);
    expect(await fs.readdir(outside)).toEqual([]);
  });

  it("a symlinked .gitignore is refused (skipped where file symlinks need privileges)", async () => {
    const victim = path.join(outside, "bashrc");
    await fs.writeFile(victim, "original\n", "utf8");
    try {
      await fs.symlink(victim, path.join(dir, ".gitignore"), "file");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EPERM") return;
      throw e;
    }
    const report = reportOf([ENV_FINDING]);
    await expect(applyFixes(report, buildRemediationPlan(report), dir, CLOCK)).rejects.toThrow(/symbolic link/);
    expect(await fs.readFile(victim, "utf8")).toBe("original\n");
  });

  it("control: a normal repo is still written", async () => {
    const report = reportOf([SQL_FINDING]);
    const res = await applyFixes(report, buildRemediationPlan(report), dir, CLOCK);
    expect(res.changed.some((c) => c.startsWith(".whsquad/fix-plan.md"))).toBe(true);
  });
});
