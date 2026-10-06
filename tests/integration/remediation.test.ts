import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../../src/cli/main.js";
import type { ScanReport } from "../../src/core/types.js";
import { makeTempDir, VULNERABLE_APP, writeTree } from "../helpers/sample-apps.js";

let stdout = "";
let stderr = "";

describe("whsquad fix", () => {
  let dir: string;
  let previousCwd: string;
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
    stdout = "";
    stderr = "";
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      stdout += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr += String(chunk);
      return true;
    });
    await writeTree(path.join(dir, "app"), VULNERABLE_APP);
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.chdir(previousCwd);
    await fs.rm(dir, { recursive: true, force: true });
  });

  const app = (rel: string): string => path.join(dir, "app", rel);
  const exists = (p: string): Promise<boolean> => fs.stat(p).then(() => true, () => false);

  it("dry run prints the ordered plan and changes nothing", async () => {
    const before = (await fs.readdir(path.join(dir, "app"), { recursive: true })).sort();
    expect(await main(["fix", "app", "--no-color"])).toBe(0);
    expect(stdout).toContain("Fix plan:");
    expect(stdout).toMatch(/1\. \[[A-Z]+\] .*(Rotate|\.env)/);
    expect(stderr).toContain("Dry run: nothing was changed");
    expect((await fs.readdir(path.join(dir, "app"), { recursive: true })).sort()).toEqual(before);
    expect(await exists(app(".whsquad"))).toBe(false);
  });

  it("--write applies only the safe additive changes, then is idempotent", async () => {
    const source = await fs.readFile(app("src/app/api/notes/[id]/route.ts"), "utf8");
    const migration = await fs.readFile(app("supabase/migrations/001_init.sql"), "utf8");
    expect(await main(["fix", "app", "--write"])).toBe(0);
    expect(stdout).toContain("Changed:");
    expect(stdout).toContain(".gitignore: appended");
    expect(stdout).toContain("whsquad verify");
    const gitignore = await fs.readFile(app(".gitignore"), "utf8");
    expect(gitignore).toContain(".env.*");
    expect(gitignore).toContain("!.env.example");
    expect(await exists(app(".whsquad/fix-plan.md"))).toBe(true);
    expect(await fs.readFile(app("src/app/api/notes/[id]/route.ts"), "utf8")).toBe(source);
    expect(await fs.readFile(app("supabase/migrations/001_init.sql"), "utf8")).toBe(migration);
    const migrations = (await fs.readdir(app("supabase/migrations"))).filter((f) => f.endsWith("_whsquad_security_fixes.sql"));

    stdout = "";
    expect(await main(["fix", "app", "--write"])).toBe(0);
    expect(await fs.readFile(app(".gitignore"), "utf8")).toBe(gitignore);
    expect((await fs.readdir(app("supabase/migrations"))).filter((f) => f.endsWith("_whsquad_security_fixes.sql"))).toEqual(migrations);
    // The plan itself changes once .env is ignored; a third run is a true no-op.
    stdout = "";
    expect(await main(["fix", "app", "--write"])).toBe(0);
    expect(stdout).toContain("(nothing)");
    expect(stdout).toContain("Left alone:");
    expect(stdout).toContain(".whsquad/fix-plan.md is already up to date");
  });

  it("--format prompt prints only the master prompt", async () => {
    expect(await main(["fix", "app", "--format", "prompt"])).toBe(0);
    expect(stdout.startsWith("You are fixing the security findings")).toBe(true);
    expect(stdout).toContain("IN ORDER");
    expect(stderr).not.toContain("Dry run");
  });

  it("--format triage prints the validation pack and can be written with --out", async () => {
    expect(await main(["fix", "app", "--format", "triage"])).toBe(0);
    expect(stdout).toContain("# whitehat-squad triage pack");
    expect(stdout).toContain("CONFIRMED");
    const out = path.join(dir, "triage.md");
    expect(await main(["fix", "app", "--format", "triage", "--out", out])).toBe(0);
    expect(await fs.readFile(out, "utf8")).toContain("triage pack");
  });

  it("--format json prints the plan and markdown the standalone document", async () => {
    expect(await main(["fix", "app", "--format", "json"])).toBe(0);
    const plan = JSON.parse(stdout) as { steps: unknown[]; masterPrompt: string };
    expect(plan.steps.length).toBeGreaterThan(0);
    stdout = "";
    expect(await main(["fix", "app", "--format", "markdown"])).toBe(0);
    expect(stdout).toContain("# whitehat-squad fix plan");
  });

  it("rejects URLs, sarif, --write with non-terminal formats and triage on scan (exit 2)", async () => {
    expect(await main(["fix", "https://example.com"])).toBe(2);
    expect(stderr).toContain("not a URL");
    expect(await main(["fix", "app", "--format", "sarif"])).toBe(2);
    expect(await main(["fix", "app", "--format", "prompt", "--write"])).toBe(2);
    expect(await main(["scan", "app", "--format", "triage"])).toBe(2);
    expect(await main(["fix", "nope-dir"])).toBe(2);
  });

  it("scan --format json carries report.remediation and verify keeps working", async () => {
    const out = path.join(dir, "r.json");
    await main(["scan", "app", "--format", "json", "--out", out]);
    const report = JSON.parse(await fs.readFile(out, "utf8")) as ScanReport;
    expect(report.remediation?.steps.length).toBeGreaterThan(0);
    expect(report.remediation?.steps[0]?.phase).toBe(1);
    stdout = "";
    await main(["scan", "app", "--no-color"]);
    expect(stdout).toMatch(/Fix plan: \d+ steps? — run `whsquad fix` to see it/);
    expect(await main(["scan", "app", "--format", "prompt"])).toBe(1);
  });

  it("a clean project gets an empty plan", async () => {
    await fs.mkdir(path.join(dir, "clean"));
    await fs.writeFile(path.join(dir, "clean", "a.ts"), "export const a = 1;\n");
    expect(await main(["fix", "clean"])).toBe(0);
    expect(stdout).toContain("nothing to fix automatically");
    expect(stderr).not.toContain("Dry run");
  });
});
