import { describe, expect, it } from "vitest";
import { ruleHelpUri, ruleMeta } from "../../../src/rules/catalog.js";
import { renderJson } from "../../../src/reporters/json.js";
import { renderMarkdown } from "../../../src/reporters/markdown.js";
import { renderSarif } from "../../../src/reporters/sarif.js";
import { renderTerminal } from "../../../src/reporters/terminal.js";
import { coverageLine } from "../../../src/reporters/util.js";
import type { Coverage } from "../../../src/core/types.js";
import { sampleFinding, sampleReport } from "../../helpers/sample-report.js";

const COVERAGE: Coverage = {
  filesIndexed: 120, filesRead: 98, filesSkippedLarge: 2, filesSkippedBinary: 5,
  truncated: false, agentsRun: 8, rulesInCatalog: 74, durationMs: 1234,
};

const authFinding = (over = {}) =>
  sampleFinding({ id: "auth-a", ruleId: "AUTH-002", severity: "high", title: "Instance title for /api/notes", explanation: "Instance explanation about /api/notes", cwe: "CWE-306", ...over });

const sarifOf = (findings: ReturnType<typeof authFinding>[], extra = {}) =>
  JSON.parse(renderSarif(sampleReport({ findings, ...extra }))).runs[0];

describe("sarif rules come from the catalog", () => {
  const run = sarifOf([authFinding(), authFinding({ id: "auth-b", title: "Instance title for /api/other" })]);
  const rule = run.tool.driver.rules.find((r: { id: string }) => r.id === "AUTH-002");
  const meta = ruleMeta("AUTH-002");

  it("emits one rule with static, instance-free text", () => {
    expect(run.tool.driver.rules.filter((r: { id: string }) => r.id === "AUTH-002")).toHaveLength(1);
    expect(rule.shortDescription.text).toBe(meta?.title);
    expect(rule.fullDescription.text).toBe(meta?.summary);
    expect(rule.help.text).toBe(meta?.fix);
    expect(rule.help.markdown).toContain(meta?.fix);
    expect(rule.helpUri).toBe(ruleHelpUri("AUTH-002"));
    expect(rule.helpUri).toBe("https://github.com/LihanCanCode/whitehat-squad/blob/main/docs/rules.md#auth-002");
    expect(JSON.stringify(rule)).not.toContain("/api/notes");
  });

  it("tags with cwe and owasp and sets security-severity from the rule's default severity", () => {
    expect(rule.properties.tags).toEqual(expect.arrayContaining(["security", "CWE-306", "external/cwe/cwe-306", "OWASP-A01"]));
    expect(rule.properties["security-severity"]).toBe("8.0");
    expect(rule.defaultConfiguration.level).toBe("error");
  });

  it.each([
    ["AI-001", "9.5"], // critical
    ["AUTH-002", "8.0"], // high
    ["WEB-L01", "5.5"], // medium
    ["WEB-004", "3.0"], // low
    ["RECON-L01", "0.0"], // info
  ])("maps %s to security-severity %s", (ruleId, score) => {
    const r = sarifOf([authFinding({ ruleId })]).tool.driver.rules[0];
    expect(r.properties["security-severity"]).toBe(score);
  });

  it("links each result to its rule by index", () => {
    const r = sarifOf([authFinding()]);
    expect(r.results[0].ruleIndex).toBe(0);
    expect(r.tool.driver.rules[r.results[0].ruleIndex].id).toBe("AUTH-002");
  });

  it("falls back to the finding's own text for a rule missing from the catalog", () => {
    const r = sarifOf([sampleFinding({ ruleId: "ZZZ-404", title: "Custom title", severity: "medium", explanation: "Custom why" })]);
    const rule = r.tool.driver.rules[0];
    expect(rule.shortDescription.text).toBe("Custom title");
    expect(rule.fullDescription.text).toBe("Custom why");
    expect(rule.properties["security-severity"]).toBe("5.5");
    expect(rule.helpUri).toBeUndefined();
  });
});

describe("sarif results", () => {
  it("downgrades low-confidence findings to note regardless of severity", () => {
    const r = sarifOf([authFinding({ id: "lo", confidence: "low" }), authFinding({ id: "hi", confidence: "medium" })]);
    const level = (id: string) => r.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === id).level;
    expect(level("lo")).toBe("note");
    expect(level("hi")).toBe("error");
  });

  it("uses the versioned fingerprint key", () => {
    const r = sarifOf([authFinding()]);
    expect(r.results[0].partialFingerprints).toEqual({ "whsquadFinding/v1": "auth-a" });
  });

  it("marks baseline findings as unchanged and leaves new ones unmarked", () => {
    const r = sarifOf([authFinding({ id: "old", baseline: true }), authFinding({ id: "new" })]);
    const byId = (id: string) => r.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === id);
    expect(byId("old").baselineState).toBe("unchanged");
    expect(byId("new").baselineState).toBeUndefined();
  });

  it("puts coverage in run.properties", () => {
    const r = sarifOf([], { coverage: COVERAGE });
    expect(r.properties.coverage).toEqual(COVERAGE);
  });

  it("omits run.properties when the report has no coverage", () => {
    expect(sarifOf([]).properties).toBeUndefined();
  });
});

describe("coverageLine", () => {
  it("summarises a static scan", () => {
    expect(coverageLine(COVERAGE, "static")).toBe("Checked 120 files with 8 agents (74 rules) in 1.2 s");
  });
  it("uses singular wording for one file and one agent", () => {
    expect(coverageLine({ ...COVERAGE, filesIndexed: 1, agentsRun: 1 }, "static")).toBe("Checked 1 file with 1 agent (74 rules) in 1.2 s");
  });
  it("summarises a live scan with its request count", () => {
    expect(coverageLine({ ...COVERAGE, filesIndexed: 0, liveRequests: 23 }, "live")).toBe(
      "Ran 8 agents (74 rules) against the live site with 23 requests in 1.2 s",
    );
  });
});

describe("terminal", () => {
  const base = sampleReport({ coverage: COVERAGE, findings: [authFinding()], agents: [{ id: "a", name: "A", findings: 1 }] });
  it("prints the coverage line, also when there are no findings", () => {
    expect(renderTerminal(base, { color: false })).toContain("Checked 120 files with 8 agents (74 rules) in 1.2 s");
    const clean = renderTerminal(sampleReport({ coverage: COVERAGE, findings: [], agents: [{ id: "a", name: "A", findings: 0 }] }), { color: false });
    expect(clean).toContain("No findings");
    expect(clean).toContain("Checked 120 files");
  });
  it("mentions skipped, truncated files", () => {
    const text = renderTerminal(sampleReport({ coverage: { ...COVERAGE, truncated: true }, findings: [] }), { color: false });
    expect(text).toContain("2 large and 5 binary files skipped");
    expect(text).toContain("file limit");
  });
  it("shows known baseline findings and the suppressed count", () => {
    const report = sampleReport({
      coverage: COVERAGE,
      findings: [authFinding({ id: "old", baseline: true }), authFinding({ id: "new" })],
      suppressed: [{ id: "s1", ruleId: "DB-001", file: "a.sql", line: 3, reason: "lookup table" }],
    });
    const text = renderTerminal(report, { color: false });
    expect(text).toContain("1 known (baseline)");
    expect(text).toContain("1 suppressed");
    expect(text).not.toContain("lookup table");
    const verbose = renderTerminal(report, { color: false, showSuppressed: true });
    expect(verbose).toContain("DB-001");
    expect(verbose).toContain("a.sql:3");
    expect(verbose).toContain("lookup table");
  });
  it("strips control characters from a suppression reason", () => {
    const report = sampleReport({ suppressed: [{ id: "s", ruleId: "DB-001", reason: "ok\u001b[31mRED" }], findings: [] });
    expect(renderTerminal(report, { color: false, showSuppressed: true })).not.toContain("\u001b[31m");
  });
  it("renders old reports without coverage", () => {
    expect(() => renderTerminal(sampleReport(), { color: false })).not.toThrow();
  });
});

describe("markdown and json", () => {
  it("adds a Coverage section and known/suppressed counts", () => {
    const md = renderMarkdown(
      sampleReport({
        coverage: COVERAGE,
        findings: [authFinding({ baseline: true })],
        suppressed: [{ id: "s1", ruleId: "DB-001", file: "a.sql", line: 3, reason: "lookup table" }],
      }),
    );
    expect(md).toContain("## Coverage");
    expect(md).toContain("Checked 120 files with 8 agents (74 rules) in 1.2 s");
    expect(md).toContain("1 known (baseline)");
    expect(md).toContain("1 suppressed");
  });
  it("includes coverage and suppressed in JSON", () => {
    const parsed = JSON.parse(renderJson(sampleReport({ coverage: COVERAGE, suppressed: [] })));
    expect(parsed.coverage).toEqual(COVERAGE);
    expect(parsed.suppressed).toEqual([]);
  });
  it("sorts findings by plain code-unit order", () => {
    const a = authFinding({ id: "x1", ruleId: "a-rule", severity: "high" });
    const b = authFinding({ id: "x2", ruleId: "B-rule", severity: "high" });
    const md = renderMarkdown(sampleReport({ findings: [a, b] }));
    expect(md.indexOf("B-rule")).toBeLessThan(md.indexOf("a-rule"));
  });
});
