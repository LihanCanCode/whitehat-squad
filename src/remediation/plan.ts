import type { Finding, RemediationPlan, RemediationStep, ScanReport, Severity } from "../core/types.js";
import { ruleMeta } from "../rules/catalog.js";
import { cmp, compareFindings, groupKeyOf, PHASE_NAMES, phaseOf } from "./phases.js";
import { masterPrompt, stepPrompt } from "./prompts.js";
import { buildMigration, dedupeSql } from "./sql.js";

const INSTALL_COMMAND = /^(?:npm|pnpm|yarn|bun)\s+\S/;

interface Group {
  readonly key: string;
  readonly phase: number;
  readonly findings: Finding[];
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const unique = <T>(items: readonly T[]): T[] => [...new Set(items)];

/** Known (baseline) and low-confidence findings are reviewed by a human, never auto-planned. */
export function needsReview(f: Finding): boolean {
  return f.baseline === true || f.confidence === "low";
}

function groupFindings(findings: readonly Finding[]): Group[] {
  const groups = new Map<string, Group>();
  for (const f of [...findings].sort(compareFindings)) {
    const key = groupKeyOf(f.ruleId);
    const existing = groups.get(key);
    if (existing) existing.findings.push(f);
    else groups.set(key, { key, phase: phaseOf(f.ruleId), findings: [f] });
  }
  return [...groups.values()].sort(
    (a, b) =>
      a.phase - b.phase ||
      compareFindings(a.findings[0] as Finding, b.findings[0] as Finding) ||
      cmp(a.key, b.key),
  );
}

function titleFor(g: Group): string {
  const n = g.findings.length;
  if (g.key === "SEC-ROTATE") return `Rotate ${plural(n, "leaked credential")}`;
  if (g.key === "SUP-010") return "Upgrade vulnerable framework versions";
  if (g.key === "DB-005") return `Pin search_path on ${plural(n, "SECURITY DEFINER function")}`;
  const base = ruleMeta(g.key)?.title ?? (g.findings[0] as Finding).title;
  return n > 1 ? `${base} (${plural(n, "finding")})` : base;
}

function rotationLines(findings: readonly Finding[]): string[] {
  return findings.map((f) => {
    const url = f.fix.references.find((r) => /^https?:\/\//.test(r));
    const at = f.evidence[0]?.file ? ` (${f.evidence[0].file}${f.evidence[0].line ? `:${f.evidence[0].line}` : ""})` : "";
    return `- Rotate: ${f.title}${at}${url ? ` at ${url}` : ""}`;
  });
}

function extraLines(g: Group): string[] {
  if (g.key === "SEC-ROTATE") {
    return [
      "Rotation list (the USER must rotate these at each provider; you cannot do it, so stop and ask first):",
      ...rotationLines(g.findings),
      "After rotation: read each replacement from a server-side environment variable only.",
    ];
  }
  if (g.key === "SEC-100") {
    return ['Add ".env", ".env.*" and "!.env.example" to .gitignore (append only), then run `git rm --cached` on the tracked env file(s).'];
  }
  return [];
}

function summaryFor(g: Group): string {
  if (g.key === "SEC-ROTATE") return `${plural(g.findings.length, "credential")} must be rotated at the provider(s) listed; removing them from code does not undo the exposure.`;
  const summaries = unique(g.findings.map((f) => f.fix.summary));
  const first = summaries[0] as string;
  return summaries.length > 1 ? `${first} (+${summaries.length - 1} similar)` : first;
}

function evidenceFiles(findings: readonly Finding[]): string[] {
  return unique(findings.flatMap((f) => f.evidence.flatMap((e) => (e.file ? [e.file] : [])))).sort(cmp);
}

function commandsOf(findings: readonly Finding[]): string[] {
  const lines = findings.flatMap((f) => (f.fix.config ?? "").split("\n").map((l) => l.trim()));
  return unique(lines.filter((l) => INSTALL_COMMAND.test(l)));
}

function severityMax(findings: readonly Finding[]): Severity {
  return (findings[0] as Finding).severity; // findings are pre-sorted, most severe first
}

function toStep(g: Group, index: number, total: number): RemediationStep {
  const title = titleFor(g);
  const ruleIds = unique(g.findings.map((f) => f.ruleId)).sort(cmp);
  const sqls = g.findings.flatMap((f) => (f.fix.sql ? [f.fix.sql] : []));
  const sql = sqls.length > 0 ? dedupeSql(sqls) : "";
  const commands = commandsOf(g.findings);
  const extra = [...extraLines(g), ...(commands.length > 0 ? ["Run:", ...commands.map((c) => `  ${c}`)] : [])];
  return {
    id: `step-${index}`,
    phase: g.phase,
    phaseName: PHASE_NAMES[g.phase - 1] as string,
    title,
    severityMax: severityMax(g.findings),
    ruleIds,
    findingIds: g.findings.map((f) => f.id),
    files: evidenceFiles(g.findings),
    summary: summaryFor(g),
    ...(sql !== "" ? { sql } : {}),
    ...(commands.length > 0 ? { commands } : {}),
    agentPrompt: stepPrompt({ index, total, title, findings: g.findings, ruleIds, extra }),
  };
}

/**
 * Pure and deterministic: the same report always yields a byte-identical plan.
 * Findings are grouped by root cause (rule + fix kind), phases are ordered by `phaseOf`, and
 * known or low-confidence findings go to `review` instead of the plan.
 */
export function buildRemediationPlan(report: ScanReport): RemediationPlan {
  const review = report.findings.filter(needsReview).sort(compareFindings).map((f) => f.id);
  const groups = groupFindings(report.findings.filter((f) => !needsReview(f)));
  const steps = groups.map((g, i) => toStep(g, i + 1, groups.length));
  const sources = steps.flatMap((s) => (s.sql ? [{ stepId: s.id, title: s.title, sql: s.sql }] : []));
  const withSql = new Set(report.findings.filter((f) => f.fix.sql).map((f) => f.id));
  const sqlIds = steps.flatMap((s) => s.findingIds).filter((id) => withSql.has(id));
  const migrationSql = buildMigration(sources, sqlIds);
  return {
    steps,
    review,
    ...(migrationSql ? { migrationSql } : {}),
    masterPrompt: masterPrompt({
      target: report.target,
      steps,
      reviewCount: review.length,
      hasMigration: migrationSql !== undefined,
    }),
  };
}
