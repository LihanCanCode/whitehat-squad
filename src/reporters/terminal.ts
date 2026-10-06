import { SEVERITIES } from "../core/severity.js";
import type { Finding, ScanReport, Severity } from "../core/types.js";
import { policyNotice } from "./policy-notice.js";
import { countBySeverity, coverageLine, coverageNotes, knownCount, locationOf, sortFindings, stripControl } from "./util.js";

export interface TerminalOptions {
  readonly color?: boolean;
  /** List findings hidden by `whsquad-ignore` comments instead of only counting them. */
  readonly showSuppressed?: boolean;
}

const SGR: Readonly<Record<Severity, string>> = {
  critical: "1;31",
  high: "31",
  medium: "33",
  low: "36",
  info: "2",
};

const oneLine = (s: string): string => stripControl(s).replace(/\s+/g, " ").trim();

export function colorEnabled(opts: TerminalOptions = {}): boolean {
  const noColor = process.env["NO_COLOR"];
  if (noColor !== undefined && noColor !== "") return false;
  if (opts.color !== undefined) return opts.color;
  // FORCE_COLOR (the common convention) colours piped output, e.g. CI logs or a recorded demo.
  const force = process.env["FORCE_COLOR"];
  if (force !== undefined && force !== "" && force !== "0" && force !== "false") return true;
  return Boolean(process.stdout.isTTY);
}

function paint(enabled: boolean, code: string, text: string): string {
  return enabled ? `\u001b[${code}m${text}\u001b[0m` : text;
}

function renderFinding(f: Finding, on: boolean): string[] {
  const sev = paint(on, SGR[f.severity], `[${f.severity.toUpperCase()}]`);
  const known = f.baseline ? paint(on, "2", " [known]") : "";
  const lines = [`${sev} ${oneLine(f.title)}  (${oneLine(f.id)})${known}`];
  const first = f.evidence[0];
  const loc = first ? locationOf(first) : undefined;
  if (loc) lines.push(`  at: ${oneLine(loc)}`);
  lines.push(`  ${oneLine(f.explanation)}`);
  lines.push(`  fix: ${oneLine(f.fix.summary)}`);
  lines.push(paint(on, "2", `  rule: ${oneLine(f.ruleId)}`));
  return lines;
}

function summaryLine(report: ScanReport): string {
  const counts = countBySeverity(report);
  const n = report.findings.length;
  const parts = SEVERITIES.map((s) => `${counts[s]} ${s}`).join(", ");
  return `${n} finding${n === 1 ? "" : "s"} (${parts})`;
}

export { policyNotice };

export function renderTerminal(report: ScanReport, opts: TerminalOptions = {}): string {
  const on = colorEnabled(opts);
  const stack = [...report.stack.frameworks, ...report.stack.backends];
  const lines: string[] = [
    paint(on, "1", "whitehat-squad scan"),
    `target: ${oneLine(report.target)}  mode: ${report.mode}  stack: ${stack.length ? stack.join(", ") : "unknown"}`,
    "",
  ];

  const errors = report.agents.filter((a) => a.error);
  if (errors.length > 0) {
    lines.push(paint(on, "33", "Warnings (some agents failed, results may be incomplete):"));
    for (const a of errors) lines.push(`  ! ${oneLine(a.name)}: ${oneLine(a.error ?? "")}`);
    lines.push("");
  }

  if (report.findings.length === 0 && errors.length > 0) {
    lines.push("Scan incomplete: no findings were reported, but some agents failed. Do not treat this as clean.", "");
  } else if (report.findings.length === 0) {
    lines.push("No findings - nice work. Remember: absence of findings is not proof of security.", "");
  } else {
    for (const f of sortFindings(report.findings)) lines.push(...renderFinding(f, on), "");
  }
  lines.push(summaryLine(report));
  const known = knownCount(report);
  if (known > 0) lines.push(`${known} known (baseline), not counted towards the exit code`);
  const suppressed = report.suppressed ?? [];
  if (suppressed.length > 0) {
    const hint = opts.showSuppressed ? ":" : " (list them with --show-suppressed)";
    lines.push(`${suppressed.length} suppressed by whsquad-ignore${hint}`);
    if (opts.showSuppressed) {
      for (const s of suppressed) {
        const where = s.file ? ` ${oneLine(s.file)}${s.line ? `:${s.line}` : ""}` : "";
        lines.push(`  ${oneLine(s.ruleId)}${where}${s.reason ? ` -- ${oneLine(s.reason)}` : ""}`);
      }
    }
  }
  const plan = report.remediation;
  if (plan && plan.steps.length > 0) {
    lines.push(`Fix plan: ${plan.steps.length} step${plan.steps.length === 1 ? "" : "s"} — run \`whsquad fix\` to see it`);
  }
  const policy = policyNotice(report);
  if (policy) lines.push(paint(on, "33", policy));
  if (report.coverage) {
    lines.push(coverageLine(report.coverage, report.mode));
    for (const note of coverageNotes(report.coverage)) lines.push(`  ${note}`);
  }
  return lines.join("\n") + "\n";
}
