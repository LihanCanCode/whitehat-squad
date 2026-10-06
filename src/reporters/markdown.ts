import type { Finding, ScanReport, Severity } from "../core/types.js";
import { SEVERITIES } from "../core/severity.js";
import { countBySeverity, coverageLine, coverageNotes, knownCount, locationOf, sortFindings } from "./util.js";
import { code, esc, escLine, fence } from "./md-util.js";
import { renderPlanSection } from "../remediation/render.js";
import { policyNotice } from "./policy-notice.js";

const BADGE: Readonly<Record<Severity, string>> = {
  critical: "\u{1F6A8}",
  high: "\u{1F534}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "ℹ️",
};

const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

function renderFinding(f: Finding): string[] {
  const out: string[] = [
    `### ${BADGE[f.severity]} ${escLine(f.title)} (${code(f.ruleId)})`,
    "",
    `**Severity:** ${f.severity} | **Confidence:** ${f.confidence} | **Found by:** ${escLine(f.agentId)}` +
      (f.cwe ? ` | **${escLine(f.cwe)}**` : ""),
    "",
    esc(f.explanation),
    "",
  ];
  if (f.evidence.length > 0) {
    out.push("**Evidence**", "");
    for (const ev of f.evidence) {
      const loc = locationOf(ev);
      if (loc) out.push(`- ${escLine(loc)}`);
      if (ev.snippet) out.push("", fence(ev.snippet), "");
    }
    out.push("");
  }
  out.push("**How to fix**", "", esc(f.fix.summary), "");
  if (f.fix.sql) out.push(fence(f.fix.sql, "sql"), "");
  if (f.fix.config) out.push(fence(f.fix.config, "text"), "");
  if (f.fix.patch) out.push(`Patch for ${escLine(f.fix.patch.file)}:`, "", fence(f.fix.patch.diff, "diff"), "");
  for (const ref of f.fix.references) out.push(`- Reference: ${escLine(ref)}`);
  if (f.fix.references.length > 0) out.push("");
  out.push("**Paste this into your coding agent**", "", fence(f.fix.agentPrompt, "text"), "");
  out.push("**Verify the fix**", "", fence(f.verify.command, "bash"), "");
  return out;
}

function coverageSection(report: ScanReport): string[] {
  const known = knownCount(report);
  const suppressed = report.suppressed ?? [];
  const notice = policyNotice(report);
  if (!report.coverage && known === 0 && suppressed.length === 0 && !notice) return [];
  const lines = ["## Coverage", ""];
  if (notice) lines.push(`> **Warning:** ${escLine(notice)}`, "");
  if (report.coverage) {
    lines.push(`- ${escLine(coverageLine(report.coverage, report.mode))}`);
    for (const note of coverageNotes(report.coverage)) lines.push(`- ${escLine(note)}`);
  }
  if (known > 0) lines.push(`- ${known} known (baseline), not counted towards the exit code`);
  if (suppressed.length > 0) lines.push(`- ${suppressed.length} suppressed by whsquad-ignore`);
  for (const s of suppressed) {
    const where = s.file ? ` ${escLine(s.file)}${s.line ? `:${s.line}` : ""}` : "";
    lines.push(`  - ${code(s.ruleId)}${where}${s.reason ? ` -- ${escLine(s.reason)}` : ""}`);
  }
  lines.push("");
  return lines;
}

export function renderMarkdown(report: ScanReport): string {
  const counts = countBySeverity(report);
  const lines: string[] = [
    "# whitehat-squad security report",
    "",
    `- **Target:** ${escLine(report.target)}`,
    `- **Mode:** ${report.mode}`,
    `- **Scanned at:** ${escLine(report.startedAt)}`,
    `- **Tool version:** ${escLine(report.version)}`,
    "",
    "## Summary",
    "",
    "| Severity | Count |",
    "| --- | --- |",
    ...SEVERITIES.map((s) => `| ${cap(s)} | ${counts[s]} |`),
    "",
    ...coverageSection(report),
    "## Squad roster",
    "",
    ...report.agents.map(
      (a) =>
        `- ${escLine(a.name)} (${code(a.id)}): ${a.findings} finding${a.findings === 1 ? "" : "s"}` +
        (a.error ? ` ⚠️ **error:** ${escLine(a.error)}` : ""),
    ),
    "",
  ];
  if (report.findings.length === 0 && report.agents.some((a) => a.error)) {
    lines.push("**Scan incomplete:** no findings were reported, but some agents failed. Do not treat this as clean.", "");
  } else if (report.findings.length === 0) {
    lines.push("No findings - nice work. Remember: absence of findings is not proof of security.", "");
  } else {
    lines.push("## Findings", "");
    for (const f of sortFindings(report.findings)) lines.push(...renderFinding(f));
  }
  if (report.remediation && (report.remediation.steps.length > 0 || report.remediation.review.length > 0)) {
    lines.push(...renderPlanSection(report.remediation));
  }
  return lines.join("\n");
}
