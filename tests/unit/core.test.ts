import { describe, expect, it } from "vitest";
import { buildIgnoreMatcher } from "../../src/core/fs-walk.js";
import { findingId, lineOf, makeFinding } from "../../src/core/finding.js";
import { runScan } from "../../src/core/orchestrator.js";
import { meetsThreshold, sarifLevel } from "../../src/core/severity.js";
import { redactSecret, scrubText } from "../../src/safety/redact.js";
import type { Agent, FileIndex } from "../../src/core/types.js";

// Built at runtime so no token-shaped literal is committed.
const LIVE = ["sk", "live", "abcdefghijklmnop"].join("_");
const emptyFiles: FileIndex = { paths: [], read: async () => null, isIgnored: () => false };

function fakeAgent(id: string, impl: Agent["run"]): Agent {
  return { id, name: id, role: "test", modes: ["static"], run: impl };
}

describe("redact", () => {
  it("keeps 4 chars on each side of a long secret", () => {
    expect(redactSecret(LIVE)).toBe("sk_l********mnop");
  });
  it("fully masks short values", () => {
    expect(redactSecret("abc")).toBe("****");
  });
  it("scrubs every occurrence, longest secret first", () => {
    const out = scrubText(`a=${LIVE} b=${LIVE}`, new Set([LIVE]));
    expect(out).not.toContain("abcdefghijkl");
  });
});

describe("gitignore matcher", () => {
  const ignored = buildIgnoreMatcher(".env\n.env.*\n!.env.example\nnode_modules/\n/dist\n*.log\n# comment\n");
  it("ignores .env variants", () => {
    expect(ignored(".env")).toBe(true);
    expect(ignored(".env.local")).toBe(true);
  });
  it("respects negation", () => {
    expect(ignored(".env.example")).toBe(false);
  });
  it("ignores nested paths under an ignored dir", () => {
    expect(ignored("node_modules/x/index.js")).toBe(true);
    expect(ignored("packages/a/node_modules/x.js")).toBe(true);
  });
  it("anchors leading-slash patterns to the root", () => {
    expect(ignored("dist/a.js")).toBe(true);
    expect(ignored("src/dist/a.js")).toBe(false);
  });
  it("matches globs and leaves normal files alone", () => {
    expect(ignored("logs/app.log")).toBe(true);
    expect(ignored("src/index.ts")).toBe(false);
  });
  it("does not treat a plain file as a dir-only match", () => {
    expect(ignored("node_modules")).toBe(false);
  });
});

describe("findings", () => {
  it("gives the same id for the same rule and location", () => {
    const ev = [{ file: "a.ts", line: 3, snippet: "x" }];
    expect(findingId("SEC-001", ev)).toBe(findingId("SEC-001", ev));
    expect(findingId("SEC-001", ev)).not.toBe(findingId("SEC-002", ev));
  });
  it("computes 1-based line numbers", () => {
    expect(lineOf("a\nb\nc", 0)).toBe(1);
    expect(lineOf("a\nb\nc", 4)).toBe(3);
  });
  it("orders severities", () => {
    expect(meetsThreshold("critical", "high")).toBe(true);
    expect(meetsThreshold("low", "high")).toBe(false);
    expect(sarifLevel("high")).toBe("error");
    expect(sarifLevel("medium")).toBe("warning");
    expect(sarifLevel("info")).toBe("note");
  });
});

describe("orchestrator", () => {
  const finding = (secret: string) =>
    makeFinding({
      ruleId: "T-001", agentId: "t", title: `leak ${secret}`, severity: "high", target: ".",
      explanation: `key ${secret}`, evidence: [{ file: "a.ts", line: 1, snippet: secret }],
      fix: { summary: "rotate", agentPrompt: `remove ${secret}`, references: [] },
    });

  it("survives one agent crashing and reports the error", async () => {
    const report = await runScan({
      mode: "static", targetLabel: ".", files: emptyFiles,
      agents: [fakeAgent("boom", async () => { throw new Error("kaboom"); }), fakeAgent("ok", async () => [finding("x")])],
    });
    expect(report.findings).toHaveLength(1);
    expect(report.agents.find((a) => a.id === "boom")?.error).toBe("kaboom");
  });

  it("scrubs registered secrets from every text field", async () => {
    const secret = LIVE;
    const report = await runScan({
      mode: "static", targetLabel: ".", files: emptyFiles,
      agents: [fakeAgent("leaky", async (ctx) => { ctx.registerSecret(secret); return [finding(secret)]; })],
    });
    expect(JSON.stringify(report)).not.toContain(secret);
  });

  it("dedupes identical findings and sorts by severity", async () => {
    const low = makeFinding({ ...{ ruleId: "L-1", agentId: "t", title: "l", severity: "low" as const, target: ".", explanation: "e", evidence: [{ snippet: "s" }], fix: { summary: "s", agentPrompt: "p", references: [] } } });
    const report = await runScan({
      mode: "static", targetLabel: ".", files: emptyFiles,
      agents: [fakeAgent("a", async () => [low, finding("k"), finding("k")])],
    });
    expect(report.findings.map((f) => f.ruleId)).toEqual(["T-001", "L-1"]);
  });

  it("skips agents that do not support the mode", async () => {
    const liveOnly: Agent = { id: "l", name: "l", role: "r", modes: ["live"], run: async () => [finding("z")] };
    const report = await runScan({ mode: "static", targetLabel: ".", files: emptyFiles, agents: [liveOnly] });
    expect(report.findings).toHaveLength(0);
  });
});
