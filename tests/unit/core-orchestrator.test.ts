import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeFinding } from "../../src/core/finding.js";
import { indexDirectory, MAX_FILE_BYTES, SKIP_DIRS } from "../../src/core/fs-walk.js";
import { runScan } from "../../src/core/orchestrator.js";
import { DETERMINISTIC_RULES } from "../../src/rules/catalog.js";
import type { Agent, Finding, Severity } from "../../src/core/types.js";
import { makeTempDir, writeTree } from "../helpers/sample-apps.js";
import { memFiles } from "../helpers/memfs.js";

function finding(over: { ruleId?: string; id?: string; evidence?: Finding["evidence"]; severity?: Severity; snippet?: string } = {}): Finding {
  const f = makeFinding({
    ruleId: over.ruleId ?? "T-001", agentId: "t", title: "t", severity: over.severity ?? "high", target: ".", explanation: "e",
    evidence: over.evidence ?? [{ file: "a.ts", line: 1, snippet: over.snippet ?? "s" }],
    fix: { summary: "s", agentPrompt: "p", references: [] },
  });
  return over.id ? { ...f, id: over.id } : f;
}
const agentOf = (id: string, ...f: Finding[]): Agent => ({ id, name: id, role: "r", modes: ["static"], run: async () => f });
const scan = (agents: Agent[]) => runScan({ mode: "static", targetLabel: ".", files: memFiles({}), agents });

describe("dedupe", () => {
  it("merges evidence of colliding findings, deduped by file:line:url, instead of dropping the later one", async () => {
    const a = finding({ id: "same", evidence: [{ file: "a.ts", line: 1, snippet: "s" }, { file: "b.ts", line: 5, snippet: "x" }] });
    const b = finding({ id: "same", evidence: [{ file: "a.ts", line: 1, snippet: "s" }, { file: "c.ts", line: 9, snippet: "y" }, { url: "https://x.test/", snippet: "u" }] });
    const r = await scan([agentOf("one", a), agentOf("two", b)]);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.evidence.map((e) => e.file ?? e.url)).toEqual(["a.ts", "b.ts", "c.ts", "https://x.test/"]);
  });

  it("keeps same-id findings at a different line as separate occurrences", async () => {
    const a = finding({ id: "same", evidence: [{ file: "a.ts", line: 1, snippet: "s" }] });
    const b = finding({ id: "same", evidence: [{ file: "a.ts", line: 7, snippet: "s" }] });
    const c = finding({ id: "same", evidence: [{ file: "a.ts", line: 7, snippet: "s" }, { file: "z.ts", line: 2, snippet: "z" }] });
    const r = await scan([agentOf("x", a, b, c)]);
    expect(r.findings).toHaveLength(2);
    const second = r.findings.find((f) => f.id !== "same");
    expect(second?.id).toBe("same~7");
    expect(second?.evidence.map((e) => e.file)).toEqual(["a.ts", "z.ts"]);
  });
});

describe("overlapping rules", () => {
  it("drops WEB-006 where INJ-007 reports the same file:line, keeping its other locations", async () => {
    const inj = finding({ ruleId: "INJ-007", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const web = finding({ ruleId: "WEB-006", evidence: [{ file: "up.ts", line: 4, snippet: "w" }, { file: "up.ts", line: 9, snippet: "v" }] });
    const r = await scan([agentOf("inj", inj), agentOf("web", web)]);
    const kept = r.findings.find((f) => f.ruleId === "WEB-006");
    expect(kept?.evidence.map((e) => e.line)).toEqual([9]);
    expect(r.findings.some((f) => f.ruleId === "INJ-007")).toBe(true);
  });

  it("removes a WEB-006 finding entirely when INJ-007 covers all of it", async () => {
    const inj = finding({ ruleId: "INJ-007", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const web = finding({ ruleId: "WEB-006", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const r = await scan([agentOf("inj", inj), agentOf("web", web)]);
    expect(r.findings.map((f) => f.ruleId)).toEqual(["INJ-007"]);
  });

  it("keeps WEB-006 when INJ-007 at the same line is excluded by policy", async () => {
    const inj = finding({ ruleId: "INJ-007", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const web = finding({ ruleId: "WEB-006", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const r = await runScan({ mode: "static", targetLabel: ".", files: memFiles({}), agents: [agentOf("inj", inj), agentOf("web", web)], policy: { exclude: ["INJ"] } });
    expect(r.findings.map((f) => f.ruleId)).toEqual(["WEB-006"]);
  });

  it("evidence without a line never overlaps", async () => {
    const inj = finding({ ruleId: "INJ-007", evidence: [{ file: "up.ts", snippet: "w" }] });
    const web = finding({ ruleId: "WEB-006", evidence: [{ file: "up.ts", snippet: "v" }] });
    const r = await scan([agentOf("inj", inj), agentOf("web", web)]);
    expect(r.findings.map((f) => f.ruleId).sort()).toEqual(["INJ-007", "WEB-006"]);
  });

  it("control: WEB-006 alone is untouched", async () => {
    const web = finding({ ruleId: "WEB-006", evidence: [{ file: "up.ts", line: 4, snippet: "w" }] });
    const r = await scan([agentOf("web", web)]);
    expect(r.findings.map((f) => f.ruleId)).toEqual(["WEB-006"]);
  });
});

describe("deterministic ordering", () => {
  it("orders by plain code-unit comparison, not locale collation", async () => {
    // localeCompare puts "a" before "B"; code-unit order puts "B" (66) before "a" (97).
    const lower = finding({ ruleId: "a-rule", snippet: "1" });
    const upper = finding({ ruleId: "B-rule", snippet: "2" });
    const r = await scan([agentOf("x", lower, upper)]);
    expect(r.findings.map((f) => f.ruleId)).toEqual(["B-rule", "a-rule"]);
  });
});

describe("coverage", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTempDir();
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("reports what was indexed, read and skipped", async () => {
    await writeTree(dir, { "a.ts": "export const a = 1;\n", "b.ts": "export const b = 2;\n", "logo.png": "not really a png" });
    await fs.writeFile(path.join(dir, "big.js"), "x".repeat(MAX_FILE_BYTES + 1));
    await fs.writeFile(path.join(dir, "blob.dat"), Buffer.from([1, 2, 0, 3]));
    const files = await indexDirectory(dir);
    const reader: Agent = {
      id: "reader", name: "reader", role: "r", modes: ["static"],
      run: async (ctx) => {
        for (const p of ctx.files.paths) await ctx.files.read(p);
        return [];
      },
    };
    const report = await runScan({ mode: "static", targetLabel: ".", root: dir, files, agents: [reader] });
    expect(report.coverage).toMatchObject({
      filesIndexed: 4,
      filesRead: 2,
      filesSkippedLarge: 1,
      filesSkippedBinary: 2,
      truncated: false,
      agentsRun: 1,
      rulesInCatalog: DETERMINISTIC_RULES.length,
    });
    expect(report.coverage?.durationMs).toBeGreaterThanOrEqual(0);
    expect(report.coverage?.liveRequests).toBeUndefined();
  });

  it("falls back to zeros for an index without counters and records live requests", async () => {
    const report = await runScan({
      mode: "static", targetLabel: ".", files: memFiles({ "a.ts": "x" }), agents: [], requestCount: () => 7,
    });
    expect(report.coverage).toMatchObject({ filesIndexed: 1, filesRead: 0, filesSkippedLarge: 0, filesSkippedBinary: 0, agentsRun: 0, liveRequests: 7 });
  });

  it("counts only agents that support the mode", async () => {
    const live: Agent = { id: "l", name: "l", role: "r", modes: ["live"], run: async () => [] };
    const report = await scan([agentOf("s"), live]);
    expect(report.coverage?.agentsRun).toBe(1);
  });
});

describe("walker skip list", () => {
  it("exports SKIP_DIRS including build and VCS directories", () => {
    for (const d of ["node_modules", ".git", "dist", ".next", ".whsquad"]) expect(SKIP_DIRS.has(d)).toBe(true);
  });
});

describe("walker skips installed third-party Python", () => {
  it("skips a pip --target dir (has *.dist-info) and a virtualenv (has pyvenv.cfg), keeps project code", async () => {
    const dir = await makeTempDir();
    try {
      await writeTree(dir, {
        "app.py": "x = 1\n",
        "vendor/py/requests/__init__.py": "x = 1\n",
        "vendor/py/requests-2.0.dist-info/METADATA": "Name: requests\n",
        "env/pyvenv.cfg": "home = /usr/bin\n",
        "env/lib/x.py": "x = 1\n",
        "pkg/mylib/__init__.py": "x = 1\n",
      });
      const index = await indexDirectory(dir);
      expect(index.paths).toEqual(["app.py", "pkg/mylib/__init__.py"]);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
