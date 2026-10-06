import { describe, expect, it } from "vitest";
import { makeFinding } from "../../src/core/finding.js";
import { runScan } from "../../src/core/orchestrator.js";
import { matchesRule, parseIgnoreDirective } from "../../src/core/suppress.js";
import type { Agent, Finding, Severity } from "../../src/core/types.js";
import { memFiles } from "../helpers/memfs.js";

describe("parseIgnoreDirective", () => {
  it.each([
    ["// whsquad-ignore SEC-090", ["SEC-090"], undefined],
    ["const x = 1; // whsquad-ignore SEC-090, DB-001 -- reviewed by me", ["SEC-090", "DB-001"], "reviewed by me"],
    ["# whsquad-ignore AUTH-002 -- internal cron", ["AUTH-002"], "internal cron"],
    ["-- whsquad-ignore DB-005 -- public lookup table", ["DB-005"], "public lookup table"],
    ["/* whsquad-ignore WEB-004 -- headers set at the CDN */", ["WEB-004"], "headers set at the CDN"],
    ["<!-- whsquad-ignore WEB-003 -->", ["WEB-003"], undefined],
    ["<!-- whsquad-ignore WEB-003 -- sanitized upstream -->", ["WEB-003"], "sanitized upstream"],
    [" * whsquad-ignore DB-* -- whole migration is test data", ["DB-*"], "whole migration is test data"],
    ["// whsquad-ignore sec-090 , db-001", ["SEC-090", "DB-001"], undefined],
  ])("parses %s", (line, rules, reason) => {
    const d = parseIgnoreDirective(line);
    expect(d?.rules).toEqual(rules);
    expect(d?.reason).toBe(reason);
  });

  it.each([
    "const s = 'whsquad-ignore SEC-090';",
    "// whsquad-ignore",
    "// whsquad-ignore everything",
    "// whsquad-ignorance SEC-090",
    "no directive here",
  ])("does not treat %s as a directive", (line) => {
    expect(parseIgnoreDirective(line)).toBeNull();
  });
});

describe("matchesRule", () => {
  it("matches exact ids and prefix wildcards only", () => {
    expect(matchesRule("DB-001", "DB-001")).toBe(true);
    expect(matchesRule("DB-*", "DB-001")).toBe(true);
    expect(matchesRule("DB-0*", "DB-001")).toBe(true);
    expect(matchesRule("DB-0*", "DB-L01")).toBe(false);
    expect(matchesRule("DB-001", "DB-0011")).toBe(false);
    expect(matchesRule("DB-*", "SEC-001")).toBe(false);
  });
});

function agentRaising(...findings: Finding[]): Agent {
  return { id: "t", name: "t", role: "r", modes: ["static"], run: async () => findings };
}

function finding(ruleId: string, file: string, line: number, severity: Severity = "high"): Finding {
  return makeFinding({
    ruleId, agentId: "t", title: `t ${ruleId}`, severity, target: ".", explanation: "e",
    evidence: [{ file, line, snippet: `snippet ${ruleId} ${line}` }],
    fix: { summary: "s", agentPrompt: "p", references: [] },
  });
}

async function scanWith(files: Record<string, string>, ...found: Finding[]) {
  return runScan({ mode: "static", targetLabel: ".", files: memFiles(files), agents: [agentRaising(...found)] });
}

describe("central suppression in the orchestrator", () => {
  it("suppresses a finding whose evidence line carries the directive, for any agent", async () => {
    const report = await scanWith(
      { "a.ts": "const a = 1;\nconst k = 2; // whsquad-ignore DB-001 -- reviewed\n" },
      finding("DB-001", "a.ts", 2),
    );
    expect(report.findings).toEqual([]);
    expect(report.suppressed).toHaveLength(1);
    expect(report.suppressed?.[0]).toMatchObject({ ruleId: "DB-001", file: "a.ts", line: 2, reason: "reviewed" });
    expect(report.suppressed?.[0]?.id).toMatch(/^[0-9a-f]{12}/);
  });

  it("suppresses when the directive is on the line directly above, in SQL comment syntax", async () => {
    const report = await scanWith(
      { "m.sql": "-- whsquad-ignore DB-* -- lookup table\ncreate table t();\n" },
      finding("DB-005", "m.sql", 2),
    );
    expect(report.findings).toHaveLength(0);
    expect(report.suppressed).toHaveLength(1);
  });

  it("does not suppress when the directive is two lines above", async () => {
    const report = await scanWith(
      { "a.ts": "// whsquad-ignore SEC-090\n\nconst k = 1;\n" },
      finding("SEC-090", "a.ts", 3),
    );
    expect(report.findings).toHaveLength(1);
    expect(report.suppressed ?? []).toEqual([]);
  });

  it("does not suppress a different rule on the same line", async () => {
    const report = await scanWith({ "a.ts": "x(); // whsquad-ignore SEC-090\n" }, finding("DB-001", "a.ts", 1));
    expect(report.findings).toHaveLength(1);
  });

  it("keeps findings that have no file or line to match", async () => {
    const live = makeFinding({
      ruleId: "WEB-L01", agentId: "t", title: "t", severity: "low", target: ".", explanation: "e",
      evidence: [{ url: "https://x.test/", snippet: "s" }], fix: { summary: "s", agentPrompt: "p", references: [] },
    });
    const report = await scanWith({}, live);
    expect(report.findings).toHaveLength(1);
  });

  it("always lists suppressed findings, with an empty array when nothing was suppressed", async () => {
    const report = await scanWith({ "a.ts": "x\n" }, finding("DB-001", "a.ts", 1));
    expect(report.suppressed).toEqual([]);
  });
});
