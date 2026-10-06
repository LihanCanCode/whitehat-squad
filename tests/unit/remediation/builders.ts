import type { Confidence, Finding, ScanReport, Severity } from "../../../src/core/types.js";

export interface F {
  id: string;
  ruleId: string;
  severity?: Severity;
  confidence?: Confidence;
  title?: string;
  file?: string;
  line?: number;
  sql?: string;
  config?: string;
  summary?: string;
  prompt?: string;
  refs?: string[];
  baseline?: boolean;
}

export function finding(o: F): Finding {
  return {
    id: o.id,
    ruleId: o.ruleId,
    agentId: "test",
    title: o.title ?? `Title of ${o.ruleId}`,
    severity: o.severity ?? "high",
    confidence: o.confidence ?? "high",
    explanation: "Because reasons.",
    evidence: o.file ? [{ file: o.file, ...(o.line ? { line: o.line } : {}), snippet: "snip" }] : [],
    fix: {
      summary: o.summary ?? `Fix ${o.ruleId}`,
      agentPrompt: o.prompt ?? `Please fix ${o.ruleId} in ${o.file ?? "the app"}.`,
      references: o.refs ?? [],
      ...(o.sql ? { sql: o.sql } : {}),
      ...(o.config ? { config: o.config } : {}),
    },
    verify: { command: `whsquad verify ${o.ruleId} .`, ruleId: o.ruleId, target: "." },
    ...(o.baseline ? { baseline: true } : {}),
  };
}

export function reportOf(findings: Finding[], overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    schemaVersion: 1,
    tool: "whitehat-squad",
    version: "0.2.0",
    target: ".",
    mode: "static",
    startedAt: "2026-01-01T00:00:00.000Z",
    stack: { frameworks: [], backends: [], routes: [] },
    agents: [{ id: "test", name: "Test", findings: findings.length }],
    findings,
    ...overrides,
  };
}
