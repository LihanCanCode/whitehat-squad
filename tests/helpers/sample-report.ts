import type { Finding, ScanReport } from "../../src/core/types.js";

export function sampleFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123def456",
    ruleId: "secrets/stripe-live-key",
    agentId: "secret-hunter",
    title: "Live Stripe key committed",
    severity: "critical",
    confidence: "high",
    explanation: "A live Stripe secret key is in your source. Anyone who reads it can charge cards.",
    evidence: [{ file: "src/lib/pay.ts", line: 12, snippet: 'const key = "sk_l********mnop";' }],
    fix: {
      summary: "Move the key to an environment variable and rotate it.",
      sql: "revoke all on table secrets from anon;",
      config: "STRIPE_SECRET_KEY=<set-me>",
      patch: { file: "src/lib/pay.ts", diff: "-const key = 'x'\n+const key = process.env.KEY" },
      agentPrompt: "Remove the hardcoded Stripe key from src/lib/pay.ts and read it from process.env.",
      references: ["https://stripe.com/docs/keys"],
    },
    verify: { command: "whsquad verify secrets/stripe-live-key .", ruleId: "secrets/stripe-live-key", target: "." },
    cwe: "CWE-798",
    ...overrides,
  };
}

export function sampleReport(overrides: Partial<ScanReport> = {}): ScanReport {
  const findings: Finding[] = [
    sampleFinding(),
    sampleFinding({
      id: "id-high-1",
      ruleId: "supabase/rls-disabled",
      agentId: "rls-inspector",
      title: "Table without RLS",
      severity: "high",
      evidence: [{ url: "https://app.example.com/rest/v1/users", snippet: "200 OK" }],
    }),
    sampleFinding({
      id: "id-high-2",
      ruleId: "supabase/rls-disabled",
      agentId: "rls-inspector",
      title: "Another table without RLS",
      severity: "high",
      evidence: [{ file: "db\\schema.sql", line: 3, snippet: "create table t();" }],
    }),
    sampleFinding({ id: "id-med", ruleId: "headers/csp", title: "Missing CSP", severity: "medium", evidence: [] }),
    sampleFinding({ id: "id-low", ruleId: "headers/xcto", title: "Missing nosniff", severity: "low" }),
    sampleFinding({ id: "id-info", ruleId: "info/stack", title: "Stack detected", severity: "info" }),
  ];
  return {
    schemaVersion: 1,
    tool: "whitehat-squad",
    version: "0.1.0",
    target: "./my-app",
    mode: "static",
    startedAt: "2026-01-01T00:00:00.000Z",
    stack: { frameworks: ["next"], backends: ["supabase"], routes: [] },
    agents: [
      { id: "secret-hunter", name: "Secret Hunter", findings: 4 },
      { id: "rls-inspector", name: "RLS Inspector", findings: 2, error: "timeout talking to db" },
    ],
    findings,
    ...overrides,
  };
}

export function emptyReport(): ScanReport {
  return sampleReport({ findings: [], agents: [{ id: "secret-hunter", name: "Secret Hunter", findings: 0 }] });
}
