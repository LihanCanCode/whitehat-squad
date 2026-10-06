import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../../src/cli/main.js";
import { makeTempDir } from "../helpers/sample-apps.js";

vi.mock("../../src/core/registry.js", async () => {
  const { makeFinding } = await import("../../src/core/finding.js");
  const finder = {
    id: "finder", name: "Finder", role: "r", modes: ["static", "live"],
    run: async () => [
      makeFinding({
        ruleId: "SEC-100", agentId: "finder", title: ".env is not git-ignored", severity: "high", target: ".", explanation: "e",
        evidence: [{ file: ".env", line: 1, snippet: "s" }], fix: { summary: "s", agentPrompt: "p", references: [] },
      }),
    ],
  };
  const crasher = { id: "crasher", name: "Crasher", role: "r", modes: ["static", "live"], run: async () => { throw new Error("boom"); } };
  return { SQUAD: [finder, crasher] };
});

describe("fix --write on an incomplete scan", () => {
  let dir: string;
  let previousCwd: string;
  let stderr = "";
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
    stderr = "";
    await fs.mkdir(path.join(dir, "app"));
    await fs.writeFile(path.join(dir, "app", ".env"), "A=1\n");
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr += String(chunk);
      return true;
    });
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.chdir(previousCwd);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("refuses to write anything and exits 4", async () => {
    expect(await main(["fix", "app", "--write"])).toBe(4);
    expect(stderr).toContain("Refusing --write");
    await expect(fs.stat(path.join(dir, "app", ".gitignore"))).rejects.toThrow();
    await expect(fs.stat(path.join(dir, "app", ".whsquad"))).rejects.toThrow();
  });

  it("a dry run still prints the plan, with a warning", async () => {
    expect(await main(["fix", "app"])).toBe(0);
    expect(stderr).toContain("Scan incomplete");
  });
});
