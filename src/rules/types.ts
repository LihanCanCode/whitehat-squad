import type { Mode, Severity } from "../core/types.js";

/**
 * Static, instance-independent description of one rule. Findings carry instance text
 * (file names, counts); the catalog carries what the rule *is*, for `explain`, SARIF and docs.
 */
export interface RuleMeta {
  /** Stable id, e.g. "DB-001". Never reused for a different check. */
  readonly id: string;
  /** Agent id that raises it, e.g. "database-guard". */
  readonly agent: string;
  /** Generic title — no file names, table names or counts. */
  readonly title: string;
  /** Default severity; individual findings may raise or lower it with a reason. */
  readonly severity: Severity;
  readonly cwe?: string;
  /** OWASP Top 10 2021 ("A01") or OWASP LLM Top 10 ("LLM01") reference. */
  readonly owasp?: string;
  /** What the rule detects and why it matters, in plain English (2-4 sentences). */
  readonly summary: string;
  /** Generic remediation guidance (instance-specific fixes live on each finding). */
  readonly fix: string;
  /** Which scan modes can raise it. */
  readonly modes: readonly Mode[];
  readonly tags?: readonly string[];
}
