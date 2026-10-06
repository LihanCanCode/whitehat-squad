import { describe, expect, it } from "vitest";
import { groupKeyOf, phaseOf } from "../../../src/remediation/phases.js";
import { buildRemediationPlan } from "../../../src/remediation/plan.js";
import { finding, reportOf } from "./builders.js";

const ROTATE_URL = "https://dashboard.stripe.com/apikeys";

function mixedReport() {
  return reportOf([
    finding({ id: "w1", ruleId: "WEB-001", severity: "low", file: "next.config.js", line: 2 }),
    finding({ id: "s1", ruleId: "SUP-010", severity: "critical", file: "package.json", line: 5, config: "npm install next@14.2.35" }),
    finding({ id: "a1", ruleId: "AUTH-002", severity: "high", file: "src/api/a.ts", line: 10 }),
    finding({ id: "d1", ruleId: "DB-001", severity: "critical", file: "supabase/migrations/1.sql", line: 1, sql: "ALTER TABLE t ENABLE ROW LEVEL SECURITY;" }),
    finding({ id: "k1", ruleId: "SEC-010", severity: "critical", title: "Hardcoded Stripe key", file: "src/pay.ts", line: 3, refs: [ROTATE_URL, "https://cwe.mitre.org"] }),
    finding({ id: "k2", ruleId: "SEC-020", severity: "critical", title: "Hardcoded OpenAI key", file: "src/ai.ts", line: 4, refs: ["https://platform.openai.com/api-keys"] }),
    finding({ id: "i1", ruleId: "INJ-001", severity: "high", file: "src/q.ts", line: 8 }),
    finding({ id: "ai1", ruleId: "AI-003", severity: "high", file: "src/chat.ts", line: 9 }),
    finding({ id: "ai2", ruleId: "AI-001", severity: "high", file: "src/chat.ts", line: 1 }),
  ]);
}

describe("phase classification", () => {
  it.each([
    ["SEC-010", 1], ["SEC-100", 1], ["DB-005", 2], ["DB-L01", 2], ["AUTH-003", 3], ["PY-012", 3],
    ["INJ-002", 4], ["AI-003", 4], ["PY-006", 4], ["SUP-010", 5], ["AI-001", 6], ["WEB-001", 7], ["supabase/rls-disabled", 7], ["PY-001", 7],
  ])("%s is phase %i", (rule, phase) => expect(phaseOf(rule)).toBe(phase));

  it("groups every leaked-credential rule together but keeps SEC-100 separate", () => {
    expect(groupKeyOf("SEC-010")).toBe("SEC-ROTATE");
    expect(groupKeyOf("SEC-101")).toBe("SEC-ROTATE");
    expect(groupKeyOf("SEC-100")).toBe("SEC-100");
    expect(groupKeyOf("DB-005")).toBe("DB-005");
  });
});

describe("buildRemediationPlan", () => {
  it("orders steps rotate, data, auth, injection, supply chain, AI, hardening", () => {
    const plan = buildRemediationPlan(mixedReport());
    expect(plan.steps.map((s) => s.ruleIds[0])).toEqual(["SEC-010", "DB-001", "AUTH-002", "AI-003", "INJ-001", "SUP-010", "AI-001", "WEB-001"]);
    expect(plan.steps.map((s) => s.phase)).toEqual([1, 2, 3, 4, 4, 5, 6, 7]);
    expect(plan.steps.map((s) => s.id)).toEqual(["step-1", "step-2", "step-3", "step-4", "step-5", "step-6", "step-7", "step-8"]);
    expect(plan.steps[0]!.phaseName).toBe("Rotate leaked secrets");
  });

  it("within a phase sorts by severity, then confidence, then rule id", () => {
    const plan = buildRemediationPlan(
      reportOf([
        finding({ id: "1", ruleId: "AUTH-005", severity: "medium" }),
        finding({ id: "2", ruleId: "AUTH-004", severity: "high", confidence: "medium" }),
        finding({ id: "3", ruleId: "AUTH-003", severity: "high", confidence: "high" }),
        finding({ id: "4", ruleId: "AUTH-001", severity: "high", confidence: "high" }),
      ]),
    );
    expect(plan.steps.map((s) => s.ruleIds[0])).toEqual(["AUTH-001", "AUTH-003", "AUTH-004", "AUTH-005"]);
  });

  it("is deterministic: the same report in any finding order gives a byte-identical plan", () => {
    const report = mixedReport();
    const reversed = reportOf([...report.findings].reverse());
    expect(JSON.stringify(buildRemediationPlan(report))).toBe(JSON.stringify(buildRemediationPlan(reversed)));
    expect(JSON.stringify(buildRemediationPlan(report))).toBe(JSON.stringify(buildRemediationPlan(report)));
  });

  it("collapses many findings of one rule into one step", () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      finding({ id: `f${i}`, ruleId: "DB-005", file: `m/${i}.sql`, line: 1, sql: `ALTER FUNCTION f${i}() SET search_path = '';` }),
    );
    const plan = buildRemediationPlan(reportOf(findings));
    expect(plan.steps).toHaveLength(1);
    const step = plan.steps[0]!;
    expect(step.title).toBe("Pin search_path on 10 SECURITY DEFINER functions");
    expect(step.findingIds).toHaveLength(10);
    expect(step.files).toHaveLength(10);
    expect(step.files).toEqual([...step.files].sort());
  });

  it("builds one rotate step listing each provider with its rotation URL", () => {
    const step = buildRemediationPlan(mixedReport()).steps[0]!;
    expect(step.title).toBe("Rotate 2 leaked credentials");
    expect(step.findingIds).toEqual(["k1", "k2"]);
    expect(step.agentPrompt).toContain(`Hardcoded Stripe key (src/pay.ts:3) at ${ROTATE_URL}`);
    expect(step.agentPrompt).toContain("https://platform.openai.com/api-keys");
    expect(step.agentPrompt).toContain("USER must rotate");
    expect(step.agentPrompt).toContain("Do not print, log, echo or commit any secret value");
  });

  it("titles a SUP-010 step and extracts the install commands", () => {
    const step = buildRemediationPlan(mixedReport()).steps.find((s) => s.ruleIds.includes("SUP-010"))!;
    expect(step.title).toBe("Upgrade vulnerable framework versions");
    expect(step.commands).toEqual(["npm install next@14.2.35"]);
    expect(step.agentPrompt).toContain("npm install next@14.2.35");
  });

  it("ignores non-install config text when collecting commands", () => {
    const plan = buildRemediationPlan(reportOf([finding({ id: "x", ruleId: "SEC-100", config: "Rotation checklist\n1. Open the dashboard" })]));
    expect(plan.steps[0]!.commands).toBeUndefined();
    expect(plan.steps[0]!.agentPrompt).toContain(".gitignore");
  });

  it("puts baseline and low-confidence findings in review, never in the steps", () => {
    const plan = buildRemediationPlan(
      reportOf([
        finding({ id: "keep", ruleId: "AUTH-002" }),
        finding({ id: "low", ruleId: "AUTH-003", confidence: "low" }),
        finding({ id: "known", ruleId: "DB-001", baseline: true, severity: "critical" }),
      ]),
    );
    expect(plan.steps.flatMap((s) => s.findingIds)).toEqual(["keep"]);
    expect(plan.review).toEqual(["known", "low"]);
    expect(plan.masterPrompt).toContain("2 findings are NOT in these steps");
    expect(plan.masterPrompt).toContain("whsquad fix --format triage");
  });

  it("uses singular wording when exactly one finding is in review", () => {
    const plan = buildRemediationPlan(reportOf([finding({ id: "a", ruleId: "AUTH-002" }), finding({ id: "b", ruleId: "AUTH-003", confidence: "low" })]));
    expect(plan.masterPrompt).toContain("1 finding is NOT in these steps");
  });

  it("merges SQL into one migration, deduplicating identical statements and listing finding ids", () => {
    const revoke = "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;";
    const plan = buildRemediationPlan(
      reportOf([
        finding({ id: "r1", ruleId: "DB-002", sql: revoke }),
        finding({ id: "r2", ruleId: "DB-002", sql: revoke }),
        finding({ id: "e1", ruleId: "DB-001", sql: `ALTER TABLE a ENABLE ROW LEVEL SECURITY;\n${revoke}\nCREATE POLICY p ON a FOR SELECT USING (true);` }),
        finding({ id: "n1", ruleId: "AUTH-002" }),
      ]),
    );
    const sql = plan.migrationSql!;
    expect(sql.split(revoke)).toHaveLength(2); // exactly one occurrence
    expect(sql).toContain("-- Addresses findings: ");
    for (const id of ["r1", "r2", "e1"]) expect(sql).toContain(id);
    expect(sql).not.toContain("n1");
    expect(sql).toContain("ENABLE ROW LEVEL SECURITY");
    expect(sql.endsWith("\n")).toBe(true);
    expect(plan.steps.find((s) => s.ruleIds.includes("DB-002"))!.sql).toBe(revoke);
  });

  it("keeps dollar-quoted function bodies intact even when statements repeat inside them", () => {
    const body = "CREATE FUNCTION f() RETURNS void AS $$\nBEGIN\n  PERFORM 1;\n  PERFORM 1;\nEND;\n$$ LANGUAGE plpgsql;";
    const plan = buildRemediationPlan(reportOf([finding({ id: "x", ruleId: "DB-005", sql: body })]));
    expect(plan.migrationSql).toContain(body);
  });

  it("omits migrationSql when no finding has SQL", () => {
    const plan = buildRemediationPlan(reportOf([finding({ id: "a", ruleId: "AUTH-002" })]));
    expect(plan.migrationSql).toBeUndefined();
  });

  it("master prompt: ordered steps, one commit each, verify, no disabling protections, stop on decisions", () => {
    const { masterPrompt } = buildRemediationPlan(mixedReport());
    expect(masterPrompt).toContain("IN ORDER");
    expect(masterPrompt).toContain("One git commit per step");
    expect(masterPrompt).toContain("whsquad verify");
    expect(masterPrompt).toContain("Never disable RLS, authentication");
    expect(masterPrompt).toContain("Never commit, print or log secrets");
    expect(masterPrompt).toContain("STOP and report");
    expect(masterPrompt).toContain("rotating a key");
    expect(masterPrompt).toContain("supabase/migrations/");
    expect(masterPrompt.indexOf("Rotate 2 leaked")).toBeLessThan(masterPrompt.indexOf("Upgrade vulnerable"));
    expect(masterPrompt.indexOf("### 1.")).toBeLessThan(masterPrompt.indexOf("### 2."));
  });

  it("step prompts say where, what not to do and how to verify", () => {
    const step = buildRemediationPlan(mixedReport()).steps.find((s) => s.ruleIds.includes("DB-001"))!;
    expect(step.agentPrompt).toContain("supabase/migrations/1.sql:1");
    expect(step.agentPrompt).toContain("Do not disable RLS");
    expect(step.agentPrompt).toContain("whsquad verify DB-001 .");
    expect(step.agentPrompt).toContain("whsquad-ignore");
  });

  it("truncates long location and guidance lists", () => {
    const findings = Array.from({ length: 30 }, (_, i) => finding({ id: `x${i}`, ruleId: "WEB-001", file: `f${i}.ts`, line: 1, prompt: `prompt ${i}` }));
    const step = buildRemediationPlan(reportOf(findings)).steps[0]!;
    expect(step.agentPrompt).toContain("...and 5 more locations");
    expect(step.agentPrompt).toContain("similar prompt(s) for the other findings");
  });

  it("falls back to the finding title for unknown rules and uses singular wording", () => {
    const plan = buildRemediationPlan(reportOf([finding({ id: "u", ruleId: "ZZZ-001", title: "Odd one" }), finding({ id: "k", ruleId: "SEC-010", refs: [] })]));
    expect(plan.steps.map((s) => s.title)).toEqual(["Rotate 1 leaked credential", "Odd one"]);
    expect(plan.steps[1]!.agentPrompt).toContain("no file location");
    expect(plan.steps[0]!.agentPrompt).toContain("- Rotate: Title of SEC-010");
  });

  it("summarises groups and tolerates evidence-less findings", () => {
    const plan = buildRemediationPlan(
      reportOf([
        finding({ id: "a", ruleId: "WEB-002", summary: "Add header A", file: "a.ts" }),
        finding({ id: "b", ruleId: "WEB-002", summary: "Add header B" }),
        finding({ id: "c", ruleId: "WEB-002", summary: "Add header B" }),
      ]),
    );
    expect(plan.steps[0]!.summary).toContain("(+1 similar)");
    expect(plan.steps[0]!.title).toMatch(/\(3 findings\)$/);
  });

  it("an empty report yields a no-op plan that tells the agent not to change code", () => {
    const plan = buildRemediationPlan(reportOf([]));
    expect(plan.steps).toEqual([]);
    expect(plan.review).toEqual([]);
    expect(plan.masterPrompt).toContain("Do not change any code");
  });
});
