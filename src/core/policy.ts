import { buildIgnoreMatcher } from "./fs-walk.js";
import { matchesRule } from "./suppress.js";
import type { Finding, ReportConfig, RuleOverride, Severity } from "./types.js";

/** User policy for one scan: config file merged with CLI flags. Everything is optional. */
export interface ScanPolicy {
  /** Config file path, only recorded in the report. */
  readonly source?: string;
  readonly failOn?: Severity;
  readonly ignorePaths?: readonly string[];
  readonly rules?: Readonly<Record<string, RuleOverride>>;
  /** Rule-id prefixes ("DB", "SEC-1"); when non-empty only matching findings are kept. */
  readonly only?: readonly string[];
  readonly exclude?: readonly string[];
  /** Baseline file path, only recorded in the report. */
  readonly baseline?: string;
  /** Finding ids already known; they are kept but marked `baseline: true`. */
  readonly baselineIds?: ReadonlySet<string>;
}

/** "db, sec-1" -> ["DB", "SEC-1"]. */
export function normalizePrefixes(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((p) => p.trim().toUpperCase())
    .filter((p) => p !== "");
}

const hasPrefix = (prefixes: readonly string[], ruleId: string): boolean =>
  prefixes.some((p) => ruleId.toUpperCase().startsWith(p));

/** Exact id beats a wildcard; among wildcards the longest (most specific) prefix wins. */
export function resolveOverride(
  rules: Readonly<Record<string, RuleOverride>>,
  ruleId: string,
): RuleOverride | undefined {
  let best: { readonly specificity: number; readonly value: RuleOverride } | undefined;
  for (const [pattern, value] of Object.entries(rules)) {
    if (!matchesRule(pattern, ruleId)) continue;
    const specificity = pattern.endsWith("*") ? pattern.length - 1 : Number.MAX_SAFE_INTEGER;
    if (!best || specificity > best.specificity) best = { specificity, value };
  }
  return best?.value;
}

export interface PolicyResult {
  readonly findings: Finding[];
  readonly config: ReportConfig;
}

export function applyPolicy(findings: readonly Finding[], policy: ScanPolicy): PolicyResult {
  const only = (policy.only ?? []).map((p) => p.toUpperCase());
  const exclude = (policy.exclude ?? []).map((p) => p.toUpperCase());
  const rules = policy.rules ?? {};
  const ignorePaths = policy.ignorePaths ?? [];
  const pathIgnored = buildIgnoreMatcher(ignorePaths.join("\n"));
  const applied = { ignoredByPath: 0, ruleOff: 0, severityOverridden: 0, filteredByPrefix: 0 };

  const out: Finding[] = [];
  for (const f of findings) {
    const files = f.evidence.flatMap((e) => (e.file ? [e.file] : []));
    if (ignorePaths.length > 0 && files.length > 0 && files.every((p) => pathIgnored(p.replace(/\\/g, "/")))) {
      applied.ignoredByPath += 1;
      continue;
    }
    if ((only.length > 0 && !hasPrefix(only, f.ruleId)) || hasPrefix(exclude, f.ruleId)) {
      applied.filteredByPrefix += 1;
      continue;
    }
    const override = resolveOverride(rules, f.ruleId);
    if (override === "off") {
      applied.ruleOff += 1;
      continue;
    }
    let next = f;
    if (override && override !== f.severity) {
      applied.severityOverridden += 1;
      next = { ...next, severity: override };
    }
    if (policy.baselineIds?.has(f.id)) next = { ...next, baseline: true };
    out.push(next);
  }

  return {
    findings: out,
    config: {
      ...(policy.source ? { source: policy.source } : {}),
      ...(policy.failOn ? { failOn: policy.failOn } : {}),
      ignorePaths: [...ignorePaths],
      rules: { ...rules },
      only: [...policy.only ?? []],
      exclude: [...policy.exclude ?? []],
      ...(policy.baseline ? { baseline: policy.baseline } : {}),
      applied,
    },
  };
}
