import { SEVERITIES } from "../core/severity.js";
import type { Coverage, Evidence, Finding, Mode, ScanReport, Severity } from "../core/types.js";

const ESC = "\u001b";
const BEL = "\u0007";

const ANSI_PATTERNS: readonly RegExp[] = [
  new RegExp(`${ESC}\\][^${BEL}${ESC}]*(?:${BEL}|${ESC}\\\\)?`, "g"), // OSC
  new RegExp(`${ESC}\\[[0-?]*[ -/]*[@-~]?`, "g"), // CSI
  new RegExp(`${ESC}[P^_X][^${ESC}]*(?:${ESC}\\\\)?`, "g"), // DCS/PM/APC/SOS
  new RegExp(`${ESC}[@-Z\\\\-_]?`, "g"), // other escapes
];
// eslint-disable-next-line no-control-regex
// Also bidi overrides and zero-width characters, which can make a hostile path read as a safe one.
const CONTROL_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g;

/** Remove ANSI escape sequences and control characters; keeps \n, turns \t into 4 spaces. */
export function stripControl(input: string): string {
  let out = input;
  for (const re of ANSI_PATTERNS) out = out.replace(re, "");
  return out.replace(/\r\n?/g, "\n").replace(/\t/g, "    ").replace(CONTROL_CHARS, "");
}

/** Code-unit order: identical on every machine, unlike localeCompare. */
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Findings ordered by severity (critical first), then ruleId, then id. Does not mutate input. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  const rank = (s: Severity): number => SEVERITIES.indexOf(s);
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity) || cmp(a.ruleId, b.ruleId) || cmp(a.id, b.id));
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const seconds = (ms: number): string => `${(ms / 1000).toFixed(1)} s`;

/** One-line "what was actually checked" summary, shown even when nothing was found. */
export function coverageLine(c: Coverage, mode: Mode): string {
  const agents = `${plural(c.agentsRun, "agent")} (${c.rulesInCatalog} rules)`;
  if (mode === "live") {
    const requests = c.liveRequests === undefined ? "" : ` with ${plural(c.liveRequests, "request")}`;
    return `Ran ${agents} against the live site${requests} in ${seconds(c.durationMs)}`;
  }
  return `Checked ${plural(c.filesIndexed, "file")} with ${agents} in ${seconds(c.durationMs)}`;
}

/** Extra coverage caveats: skipped files and the file cap. Empty when nothing was skipped. */
export function coverageNotes(c: Coverage): string[] {
  const notes: string[] = [];
  if (c.filesSkippedLarge > 0 || c.filesSkippedBinary > 0) {
    notes.push(`${c.filesSkippedLarge} large and ${c.filesSkippedBinary} binary files skipped`);
  }
  if (c.truncated) notes.push("file limit reached: not every file was scanned");
  return notes;
}

export function knownCount(report: ScanReport): number {
  return report.findings.filter((f) => f.baseline === true).length;
}

export function countBySeverity(report: ScanReport): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) counts[f.severity] += 1;
  return counts;
}

export function locationOf(ev: Evidence): string | undefined {
  if (ev.file) return ev.line ? `${ev.file}:${ev.line}` : ev.file;
  return ev.url;
}
