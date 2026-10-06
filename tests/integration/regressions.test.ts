import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../../src/cli/main.js";
import { findingId, makeFinding } from "../../src/core/finding.js";
import { runScan, shellQuote } from "../../src/core/orchestrator.js";
import { renderReport } from "../../src/reporters/index.js";
import type { Agent, FileIndex } from "../../src/core/types.js";
import { makeTempDir, VULNERABLE_APP, writeTree } from "../helpers/sample-apps.js";

const NO_FILES: FileIndex = { paths: [], read: async () => null, isIgnored: () => false };
const crashing: Agent = { id: "boom", name: "Boom", role: "r", modes: ["static"], run: () => { throw new Error("sync kaboom"); } };

const finding = (title: string, snippet: string, line: number, file = "a.ts") =>
  makeFinding({
    ruleId: "T-001", agentId: "t", title, severity: "high", target: "/abs/path with space",
    explanation: "explain", evidence: [{ file, line, snippet }],
    fix: { summary: "s", agentPrompt: "p", references: [] },
  });

describe("failed agents are never reported as clean", () => {
  it("isolates a synchronous throw and flags the report as incomplete", async () => {
    const report = await runScan({ mode: "static", targetLabel: ".", files: NO_FILES, agents: [crashing] });
    expect(report.agents[0]?.error).toBe("sync kaboom");
    expect(renderReport(report, "terminal", { color: false })).toContain("Scan incomplete");
    expect(renderReport(report, "terminal", { color: false })).not.toContain("nice work");
    expect(renderReport(report, "markdown")).toContain("Scan incomplete");
    const sarif = JSON.parse(renderReport(report, "sarif"));
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(false);
    expect(sarif.runs[0].invocations[0].toolExecutionNotifications[0].message.text).toContain("Boom");
  });
});

describe("finding ids", () => {
  it("survive unrelated edits that shift line numbers", () => {
    expect(findingId("R", [{ file: "a.ts", line: 3, snippet: "x" }], "t")).toBe(
      findingId("R", [{ file: "a.ts", line: 40, snippet: "x" }], "t"),
    );
  });

  it("keep two different findings of one rule in one file apart", async () => {
    const report = await runScan({
      mode: "static", targetLabel: ".", files: NO_FILES,
      agents: [{ id: "a", name: "a", role: "r", modes: ["static"], run: async () => [finding("one", "key1", 1), finding("two", "key2", 1)] }],
    });
    expect(report.findings).toHaveLength(2);
  });

  it("keep identical snippets on different lines as separate occurrences", async () => {
    const report = await runScan({
      mode: "static", targetLabel: ".", files: NO_FILES,
      agents: [{ id: "a", name: "a", role: "r", modes: ["static"], run: async () => [finding("same", "dup", 1), finding("same", "dup", 9)] }],
    });
    expect(report.findings).toHaveLength(2);
    expect(new Set(report.findings.map((f) => f.id)).size).toBe(2);
  });
});

describe("verify commands", () => {
  it("use the target as typed, quoted, never an agent's absolute path", async () => {
    const report = await runScan({
      mode: "static", targetLabel: "my app", files: NO_FILES, platform: "linux",
      agents: [{ id: "a", name: "a", role: "r", modes: ["static"], run: async () => [finding("x", "s", 1)] }],
    });
    expect(report.findings[0]?.verify.command).toBe("whsquad verify T-001 'my app'");
    expect(report.findings[0]?.verify.command).not.toContain("/abs/path");
  });

  it("shell-quote hostile paths", () => {
    expect(shellQuote("src", "linux")).toBe("src");
    expect(shellQuote("a b", "linux")).toBe("'a b'");
    expect(shellQuote("it's; rm -rf /", "linux")).toBe(`'it'\\''s; rm -rf /'`);
  });
});

describe("SARIF uris", () => {
  it("percent-encode path segments such as Next.js route groups", async () => {
    const report = await runScan({
      mode: "static", targetLabel: ".", files: NO_FILES,
      agents: [{ id: "a", name: "a", role: "r", modes: ["static"], run: async () => [finding("x", "s", 1, "app/(auth)/[id]/my page.tsx")] }],
    });
    const uri = JSON.parse(renderReport(report, "sarif")).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe("app/(auth)/%5Bid%5D/my%20page.tsx");
  });
});

describe("verify guards", () => {
  let dir: string;
  let previousCwd: string;
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
    await writeTree(path.join(dir, "one"), VULNERABLE_APP);
    await writeTree(path.join(dir, "two"), { "package.json": "{}" });
  });
  afterEach(async () => {
    process.chdir(previousCwd);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("refuses to verify a different target than the last scan", async () => {
    expect(await main(["scan", "one", "--format", "json", "--out", path.join(dir, "r.json")])).toBe(1);
    expect(await main(["verify", "DB-001", "two"])).toBe(2);
  });

  it("refuses a rule that had no findings (typo or never fired)", async () => {
    expect(await main(["scan", "one", "--format", "json", "--out", path.join(dir, "r.json")])).toBe(1);
    expect(await main(["verify", "SEC-999", "one"])).toBe(2);
  });

  it("accepts lower-case rule ids", async () => {
    expect(await main(["scan", "one", "--format", "json", "--out", path.join(dir, "r.json")])).toBe(1);
    expect(await main(["verify", "db-001", "one"])).toBe(1);
  });
});
