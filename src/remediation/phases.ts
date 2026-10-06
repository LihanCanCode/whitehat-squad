import type { Confidence, Finding, Severity } from "../core/types.js";

/**
 * Remediation priority order. Lower phase number = fixed first.
 *
 *  1. Rotate / revoke leaked secrets   - exposure already happened and is permanent; nothing else matters until the key is dead.
 *  2. Close data exposure              - database (DB-*), storage buckets, Firebase rules: anyone can read or write user data.
 *  3. Authentication / authorization   - AUTH-*, plus Python auth, CSRF, CORS, JWT and password-hashing rules.
 *  4. Injection and code execution     - INJ-*, AI-003 (model output reaching a sink), Python injection / SSRF / traversal.
 *  5. Supply chain and CI              - SUP-*: vulnerable or malicious dependencies, risky workflows.
 *  6. AI cost and abuse                - the remaining AI-* rules (unbounded spend, prompt abuse, key exposure to clients).
 *  7. Hardening                        - WEB-*, headers, debug flags, recon, anything not classified above.
 *
 * Within a phase: severity (critical first), then confidence (high first), then ruleId.
 */
export const PHASE_NAMES: readonly string[] = [
  "Rotate leaked secrets",
  "Close data exposure",
  "Authentication and authorization",
  "Injection and code execution",
  "Supply chain and CI",
  "AI cost and abuse",
  "Hardening",
];

const PY_AUTH = new Set(["PY-004", "PY-005", "PY-012", "PY-013", "PY-014", "PY-015"]);
const PY_INJECTION = new Set(["PY-006", "PY-007", "PY-008", "PY-009", "PY-010", "PY-011"]);

/** 1-based phase number for a rule id. Unknown rules fall into hardening. */
export function phaseOf(ruleId: string): number {
  if (ruleId.startsWith("SEC-") || ruleId === "PY-003") return 1;
  if (ruleId.startsWith("DB-")) return 2;
  if (ruleId.startsWith("AUTH-") || PY_AUTH.has(ruleId)) return 3;
  if (ruleId.startsWith("INJ-") || ruleId === "AI-003" || PY_INJECTION.has(ruleId)) return 4;
  if (ruleId.startsWith("SUP-")) return 5;
  if (ruleId.startsWith("AI-")) return 6;
  // AI review classes: cross-file injection, AI steering, and the authorization / logic family.
  if (ruleId === "REV-006") return 4;
  if (ruleId === "REV-008") return 6;
  if (ruleId.startsWith("REV-")) return 3;
  return 7;
}

/** Leaked credentials (not the .env-tracking rule) share one "rotate" step. */
export function groupKeyOf(ruleId: string): string {
  return ruleId.startsWith("SEC-") && ruleId !== "SEC-100" ? "SEC-ROTATE" : ruleId;
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = { high: 0, medium: 1, low: 2 };

export const severityRank = (s: Severity): number => SEVERITY_RANK[s];
export const confidenceRank = (c: Confidence): number => CONFIDENCE_RANK[c];

/** Code-unit order: identical on every machine. */
export const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Severity, then confidence, then ruleId, then id. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
    cmp(a.ruleId, b.ruleId) ||
    cmp(a.id, b.id)
  );
}
