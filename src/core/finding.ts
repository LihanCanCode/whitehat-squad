import { createHash } from "node:crypto";
import type { Confidence, Evidence, Finding, Fix, Severity } from "./types.js";

export interface FindingInput {
  readonly ruleId: string;
  readonly agentId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence?: Confidence;
  readonly explanation: string;
  readonly evidence: readonly Evidence[];
  readonly fix: Fix;
  readonly target: string;
  readonly cwe?: string;
}

/**
 * Stable id for verify + SARIF. Built from the rule, the file/url and the (already redacted)
 * evidence snippet, not the line number, so unrelated edits above a finding do not change it
 * and two different findings in one file do not collide.
 */
export function findingId(ruleId: string, evidence: readonly Evidence[], title = ""): string {
  const first = evidence[0];
  const where = first ? `${first.file ?? first.url ?? ""}|${first.snippet}` : "";
  return createHash("sha1").update(`${ruleId}|${where}|${title}`).digest("hex").slice(0, 12);
}

export function makeFinding(input: FindingInput): Finding {
  return {
    id: findingId(input.ruleId, input.evidence, input.title),
    ruleId: input.ruleId,
    agentId: input.agentId,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence ?? "high",
    explanation: input.explanation,
    evidence: input.evidence,
    fix: input.fix,
    verify: {
      command: `whsquad verify ${input.ruleId} ${input.target}`,
      ruleId: input.ruleId,
      target: input.target,
    },
    ...(input.cwe ? { cwe: input.cwe } : {}),
  };
}

/** 1-based line number of a character offset. */
export function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}
