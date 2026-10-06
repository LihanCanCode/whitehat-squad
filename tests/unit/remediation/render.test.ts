import { describe, expect, it } from "vitest";
import { renderPlanDocument, renderPlanSection, renderPlanText } from "../../../src/remediation/render.js";
import { buildRemediationPlan } from "../../../src/remediation/plan.js";
import { renderMarkdown } from "../../../src/reporters/markdown.js";
import { renderReport } from "../../../src/reporters/index.js";
import { renderTerminal } from "../../../src/reporters/terminal.js";
import { dedupeSql } from "../../../src/remediation/sql.js";
import { finding, reportOf } from "./builders.js";

const FINDINGS = [
  finding({ id: "d1", ruleId: "DB-001", severity: "critical", sql: "ALTER TABLE t ENABLE ROW LEVEL SECURITY;", file: "a.sql", line: 1 }),
  finding({ id: "s1", ruleId: "SUP-010", config: "npm install next@14.2.35", file: "package.json" }),
  finding({ id: "r1", ruleId: "AUTH-002", confidence: "low" }),
];

describe("plan rendering", () => {
  const plan = buildRemediationPlan(reportOf(FINDINGS));

  it("renders text for the terminal with steps, commands, review hint and SQL", () => {
    const text = renderPlanText(plan);
    expect(text).toContain("Fix plan: 2 steps covering 2 findings");
    expect(text).toContain("1. [CRITICAL]");
    expect(text).toContain("run: npm install next@14.2.35");
    expect(text).toContain("1 finding need review first");
    expect(text).toContain("Merged SQL migration:");
  });

  it("renders the no-op plan", () => {
    expect(renderPlanText(buildRemediationPlan(reportOf([])))).toContain("nothing to fix automatically");
    expect(renderPlanSection(buildRemediationPlan(reportOf([]))).join("\n")).toContain("Nothing to fix automatically.");
  });

  it("renders a markdown section with ordered steps, a fenced SQL block and a fenced master prompt", () => {
    const md = renderPlanSection(plan).join("\n");
    expect(md).toContain("## Fix plan");
    expect(md.indexOf("### 1.")).toBeLessThan(md.indexOf("### 2."));
    expect(md).toContain("```sql\n");
    expect(md).toContain("### Merged SQL migration");
    expect(md).toContain("### Master prompt");
    expect(md).toContain("```text\n");
    expect(md).toContain("### Review before acting");
  });

  it("uses a longer fence when the prompt itself contains backticks", () => {
    const tricky = buildRemediationPlan(reportOf([finding({ id: "x", ruleId: "AUTH-002", prompt: "run ```rm -rf``` never" })]));
    expect(renderPlanDocument(tricky, ".")).toContain("````text");
  });

  it("neutralises hostile markup in finding titles", () => {
    const hostile = buildRemediationPlan(reportOf([finding({ id: "x", ruleId: "ZZZ-1", title: "<script>alert(1)</script>" })]));
    const md = renderPlanDocument(hostile, "<x>");
    expect(md).toContain("## 1. &lt;script&gt;");
    expect(md).toContain("&lt;script&gt;");
  });
});

describe("reporters carry the plan", () => {
  const base = reportOf(FINDINGS);
  const withPlan = { ...base, remediation: buildRemediationPlan(base) };

  it("markdown gains a Fix plan section only when the report has a plan", () => {
    expect(renderMarkdown(withPlan)).toContain("## Fix plan");
    expect(renderMarkdown(base)).not.toContain("## Fix plan");
  });

  it("terminal prints the one-line pointer", () => {
    expect(renderTerminal(withPlan, { color: false })).toContain("Fix plan: 2 steps — run `whsquad fix` to see it");
    expect(renderTerminal(base, { color: false })).not.toContain("Fix plan:");
    const empty = { ...base, remediation: buildRemediationPlan(reportOf([])) };
    expect(renderTerminal(empty, { color: false })).not.toContain("Fix plan:");
  });

  it("json includes report.remediation", () => {
    const parsed = JSON.parse(renderReport(withPlan, "json")) as { remediation: { steps: unknown[]; masterPrompt: string } };
    expect(parsed.remediation.steps).toHaveLength(2);
    expect(parsed.remediation.masterPrompt).toContain("IN ORDER");
  });

  it("prompt format prints only the master prompt, computing the plan when absent", () => {
    expect(renderReport(withPlan, "prompt")).toBe(withPlan.remediation.masterPrompt + "\n");
    expect(renderReport(base, "prompt")).toBe(withPlan.remediation.masterPrompt + "\n");
  });
});

describe("dedupeSql", () => {
  it("drops repeated statements, keeps order and comment-only chunks, and ignores blanks", () => {
    const out = dedupeSql(["A;\nB;", "B;\n-- trailing note", "\n\n", "-- trailing note\nC;"]);
    expect(out).toBe("A;\nB;\n-- trailing note\n-- trailing note\nC;");
  });
});
