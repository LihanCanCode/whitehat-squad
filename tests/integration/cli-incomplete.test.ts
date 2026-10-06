import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../../src/cli/main.js";
import { makeTempDir } from "../helpers/sample-apps.js";

// The registry is replaced so one agent can crash while another raises a real finding.
vi.mock("../../src/core/registry.js", async () => {
  const { makeFinding } = await import("../../src/core/finding.js");
  const finder = {
    id: "finder", name: "Finder", role: "r", modes: ["static", "live"],
    run: async () => [
      makeFinding({
        ruleId: "AUTH-002", agentId: "finder", title: "t", severity: "high", target: ".", explanation: "e",
        evidence: [{ file: "a.ts", line: 1, snippet: "s" }], fix: { summary: "s", agentPrompt: "p", references: [] },
      }),
    ],
  };
  const crasher = { id: "crasher", name: "Crasher", role: "r", modes: ["static", "live"], run: async () => { throw new Error("boom"); } };
  return { SQUAD: [finder, crasher] };
});

describe("incomplete scans", () => {
  let dir: string;
  let previousCwd: string;
  let stderr = "";
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
    stderr = "";
    await fs.mkdir(path.join(dir, "app"));
    await fs.writeFile(path.join(dir, "app", "a.ts"), "export const a = 1;\n");
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

  it("still exits 1 for findings but warns on stderr that the scan was incomplete", async () => {
    expect(await main(["scan", "app", "--format", "json"])).toBe(1);
    expect(stderr).toContain("Scan incomplete");
  });

  it("exits 4 and warns when the incomplete scan has nothing failing", async () => {
    expect(await main(["scan", "app", "--format", "json", "--fail-on", "critical"])).toBe(4);
    expect(stderr).toContain("Scan incomplete");
  });

  it("does not write a baseline from an incomplete scan", async () => {
    expect(await main(["baseline", "app"])).toBe(4);
    await expect(fs.stat(path.join(dir, ".whsquad", "baseline.json"))).rejects.toThrow();
  });
});
