import type { ScanReport } from "../core/types.js";
import { buildRemediationPlan } from "../remediation/plan.js";
import { renderJson } from "./json.js";
import { renderMarkdown } from "./markdown.js";
import { renderSarif } from "./sarif.js";
import { renderTerminal } from "./terminal.js";

export type ReportFormat = "terminal" | "json" | "sarif" | "markdown" | "prompt";

const FORMATS: readonly string[] = ["terminal", "json", "sarif", "markdown", "prompt"];

export function isReportFormat(s: string): s is ReportFormat {
  return FORMATS.includes(s);
}

export function renderReport(report: ScanReport, format: ReportFormat, opts: { color?: boolean; showSuppressed?: boolean } = {}): string {
  switch (format) {
    case "json":
      return renderJson(report);
    case "sarif":
      return renderSarif(report);
    case "markdown":
      return renderMarkdown(report);
    case "prompt":
      return (report.remediation ?? buildRemediationPlan(report)).masterPrompt + "\n";
    case "terminal":
      return renderTerminal(report, opts);
  }
}
