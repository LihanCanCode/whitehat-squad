import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../../src/cli/main.js";
import { indexDirectory } from "../../src/core/fs-walk.js";
import { runScan } from "../../src/core/orchestrator.js";
import { SEVERITY_ORDER } from "../../src/core/severity.js";
import type { ScanReport } from "../../src/core/types.js";
import { CLEAN_APP, FAKE_STRIPE_KEY, makeTempDir, VULNERABLE_APP, writeTree } from "../helpers/sample-apps.js";

async function scanDir(dir: string): Promise<ScanReport> {
  return runScan({ mode: "static", targetLabel: ".", root: dir, files: await indexDirectory(dir) });
}

describe("scanning real directories", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTempDir();
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("finds the planted holes in a vulnerable vibe-coded app", async () => {
    await writeTree(dir, VULNERABLE_APP);
    const report = await scanDir(dir);
    const rules = new Set(report.findings.map((f) => f.ruleId));
    for (const expected of ["DB-001", "SEC-100", "SUP-001", "AUTH-003", "AI-001", "AI-007"]) {
      expect(rules, `expected ${expected}`).toContain(expected);
    }
    expect(report.findings.some((f) => f.ruleId.startsWith("SEC-0") && f.severity === "critical")).toBe(true);
    expect(report.agents.every((a) => !a.error)).toBe(true);
  });

  it("never leaks a raw secret into any report format", async () => {
    await writeTree(dir, VULNERABLE_APP);
    const report = await scanDir(dir);
    expect(JSON.stringify(report)).not.toContain(FAKE_STRIPE_KEY);
    expect(JSON.stringify(report)).not.toContain(FAKE_STRIPE_KEY.slice(4, -4));
  });

  it("gives every finding an explanation, a fix, an agent prompt and a verify command", async () => {
    await writeTree(dir, VULNERABLE_APP);
    const report = await scanDir(dir);
    for (const f of report.findings) {
      expect(f.explanation.length, f.ruleId).toBeGreaterThan(30);
      expect(f.fix.summary, f.ruleId).not.toBe("");
      expect(f.fix.agentPrompt, f.ruleId).not.toBe("");
      expect(f.verify.command, f.ruleId).toContain(f.ruleId);
    }
  });

  it("reports nothing above info on a well-built app (false-positive guard)", async () => {
    await writeTree(dir, CLEAN_APP);
    const report = await scanDir(dir);
    const noisy = report.findings.filter((f) => SEVERITY_ORDER[f.severity] > SEVERITY_ORDER.info);
    expect(noisy.map((f) => `${f.ruleId} ${f.title}`)).toEqual([]);
  });
});

describe("CLI end to end", () => {
  let dir: string;
  let previousCwd: string;
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
  });
  afterEach(async () => {
    process.chdir(previousCwd);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("exits 1 on findings, writes a valid SARIF file, and 0 when clean", async () => {
    await writeTree(path.join(dir, "bad"), VULNERABLE_APP);
    await writeTree(path.join(dir, "good"), CLEAN_APP);
    const sarifPath = path.join(dir, "out.sarif");

    expect(await main(["scan", "bad", "--format", "sarif", "--out", sarifPath])).toBe(1);
    const sarif = JSON.parse(await fs.readFile(sarifPath, "utf8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);

    expect(await main(["scan", "good", "--format", "json", "--out", path.join(dir, "good.json")])).toBe(0);
  });

  it("closes the loop: scan, apply the fix, verify reports it fixed", async () => {
    await writeTree(path.join(dir, "app"), VULNERABLE_APP);
    expect(await main(["scan", "app", "--format", "json", "--out", path.join(dir, "r.json")])).toBe(1);
    expect(await main(["verify", "DB-001", "app"])).toBe(1);

    const migration = path.join(dir, "app/supabase/migrations/001_init.sql");
    await fs.appendFile(
      migration,
      "alter table public.profiles enable row level security;\nalter table public.notes enable row level security;\n" +
        "create policy p on public.profiles for all using (auth.uid() = user_id);\n" +
        "create policy n on public.notes for all using (auth.uid() = user_id);\n",
    );
    expect(await main(["verify", "DB-001", "app"])).toBe(0);
  });

  it("refuses a live scan of a site whose ownership is not proven (exit 3)", async () => {
    expect(await main(["scan", "https://whsquad-ownership-test.invalid"])).toBe(3);
  });

  it("returns usage errors with exit 2", async () => {
    expect(await main(["scan"])).toBe(2);
    expect(await main(["scan", "does-not-exist"])).toBe(2);
    expect(await main(["scan", ".", "--format", "pdf"])).toBe(2);
    expect(await main(["bogus"])).toBe(2);
    expect(await main(["verify", "DB-001", "."])).toBe(2);
  });

  it("prints help and version", async () => {
    expect(await main(["--help"])).toBe(0);
    expect(await main(["--version"])).toBe(0);
    expect(await main(["agents"])).toBe(0);
  });
});
