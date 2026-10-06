import { sarifLevel } from "../core/severity.js";
import type { Evidence, Finding, ScanReport, Severity } from "../core/types.js";
import { ruleHelpUri, ruleMeta } from "../rules/catalog.js";
import type { RuleMeta } from "../rules/types.js";
import { policyNotice } from "./policy-notice.js";
import { sortFindings } from "./util.js";

const INFORMATION_URI = "https://github.com/LihanCanCode/whitehat-squad";

/** Relative POSIX path: forward slashes, no drive letter, no leading slash or ./ */
function toRelativeUri(file: string): string {
  return file
    .replace(/\\/g, "/")
    .replace(/^[A-Za-z]:/, "")
    .replace(/^(?:\.?\/)+/, "")
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}

function locationFor(ev: Evidence): object | undefined {
  if (ev.file) {
    const region = ev.line && ev.line > 0 ? { region: { startLine: ev.line } } : {};
    return { physicalLocation: { artifactLocation: { uri: toRelativeUri(ev.file) }, ...region } };
  }
  if (ev.url) return { physicalLocation: { artifactLocation: { uri: ev.url } } };
  return undefined;
}

/** GitHub code scanning sorts by this CVSS-like score (as a string). */
const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

function ruleTags(cwe: string | undefined, owasp: string | undefined, extra: readonly string[] = []): string[] {
  return [
    "security",
    ...(cwe ? [cwe, `external/cwe/${cwe.toLowerCase()}`] : []),
    ...(owasp ? [`OWASP-${owasp}`] : []),
    ...extra,
  ];
}

/** Static text from the catalog: the same for every instance, so GitHub shows one stable rule page. */
function catalogRule(meta: RuleMeta): object {
  return {
    id: meta.id,
    name: meta.id,
    shortDescription: { text: meta.title },
    fullDescription: { text: meta.summary },
    help: { text: meta.fix, markdown: `**${meta.title}**

${meta.summary}

**How to fix:** ${meta.fix}` },
    helpUri: ruleHelpUri(meta.id),
    defaultConfiguration: { level: sarifLevel(meta.severity) },
    properties: { tags: ruleTags(meta.cwe, meta.owasp, meta.tags), "security-severity": SECURITY_SEVERITY[meta.severity] },
  };
}

/** Rule missing from the catalog (custom agent, older report): fall back to the first finding's text. */
function fallbackRule(f: Finding): object {
  return {
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: f.title },
    fullDescription: { text: f.explanation },
    help: { text: f.fix.summary },
    defaultConfiguration: { level: sarifLevel(f.severity) },
    properties: { tags: ruleTags(f.cwe, undefined), "security-severity": SECURITY_SEVERITY[f.severity] },
  };
}

function buildRules(findings: readonly Finding[]): { rules: object[]; index: ReadonlyMap<string, number> } {
  const seen = new Map<string, Finding>();
  for (const f of findings) if (!seen.has(f.ruleId)) seen.set(f.ruleId, f);
  const ordered = [...seen.values()].sort((a, b) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
  const rules = ordered.map((f) => {
    const meta = ruleMeta(f.ruleId);
    return meta ? catalogRule(meta) : fallbackRule(f);
  });
  return { rules, index: new Map(ordered.map((f, i) => [f.ruleId, i])) };
}

/** Low-confidence heuristics are "note" whatever their severity, so they never break a code-scanning gate. */
function resultLevel(f: Finding): "error" | "warning" | "note" {
  if (f.confidence === "low") return "note";
  // Advisory AI findings never reach "error", so they cannot fail a code-scanning gate.
  if (f.origin === "ai") return "warning";
  return sarifLevel(f.severity);
}

function buildResult(f: Finding, ruleIndex: number | undefined): object {
  const locations = f.evidence.map(locationFor).filter((l): l is object => l !== undefined);
  return {
    ruleId: f.ruleId,
    ...(ruleIndex !== undefined ? { ruleIndex } : {}),
    level: resultLevel(f),
    message: { text: `${f.title}: ${f.explanation}` },
    ...(locations.length > 0 ? { locations } : {}),
    partialFingerprints: { "whsquadFinding/v1": f.id },
    ...(f.baseline ? { baselineState: "unchanged" } : {}),
    properties: {
      severity: f.severity, confidence: f.confidence, agent: f.agentId,
      // AI review findings are advisory and model-produced: say so wherever the SARIF is consumed.
      ...(f.origin === "ai" ? { origin: "ai", reviewModel: f.reviewModel, reviewState: f.reviewState, tags: ["ai-review"] } : {}),
    },
  };
}

/**
 * A crashed agent means the scan was incomplete, and a repo policy or inline suppressions may have
 * hidden findings: say both, so CI never reads either as clean.
 */
function buildInvocation(report: ScanReport): object {
  const failed = report.agents.filter((a) => a.error);
  const notice = policyNotice(report);
  const suppressed = report.suppressed?.length ?? 0;
  return {
    executionSuccessful: failed.length === 0,
    toolExecutionNotifications: [
      ...failed.map((a) => ({ level: "error", message: { text: `Agent ${a.name} failed: ${a.error ?? "unknown error"}` } })),
      ...(notice ? [{ level: "warning", message: { text: notice } }] : []),
      ...(suppressed > 0 ? [{ level: "note", message: { text: `${suppressed} finding${suppressed === 1 ? "" : "s"} suppressed by whsquad-ignore comments.` } }] : []),
    ],
  };
}

export function renderSarif(report: ScanReport): string {
  const findings = sortFindings(report.findings);
  const { rules, index } = buildRules(findings);
  const doc = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "whitehat-squad",
            version: report.version,
            informationUri: INFORMATION_URI,
            rules,
          },
        },
        invocations: [buildInvocation(report)],
        results: findings.map((f) => buildResult(f, index.get(f.ruleId))),
        ...(report.coverage ? { properties: { coverage: report.coverage } } : {}),
      },
    ],
  };
  return JSON.stringify(doc, null, 2) + "\n";
}
