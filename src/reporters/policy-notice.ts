import type { ScanReport } from "../core/types.js";
import { knownCount, stripControl } from "./util.js";

const oneLine = (s: string): string => stripControl(s).replace(/\s+/g, " ").trim();

/**
 * A scanned repository can switch its own rules off (whsquad.config.json), filter them, baseline
 * them or relax failOn. That is legitimate for its owner and a hiding place for anyone else, so every
 * reporter (terminal, markdown, SARIF) says so. Returns undefined when the policy changed nothing.
 */
export function policyNotice(report: ScanReport): string | undefined {
  const c = report.config;
  if (!c) return undefined;
  const hidden = c.applied.ruleOff + c.applied.ignoredByPath + c.applied.filteredByPrefix;
  const known = c.baseline ? knownCount(report) : 0;
  const relaxed = c.source !== undefined && c.failOn === "critical";
  const fromPolicy = c.applied.ruleOff + c.applied.ignoredByPath + c.applied.severityOverridden + known > 0 || relaxed;
  if (!fromPolicy) {
    // --only / --exclude are typed by the person running the scan: say so plainly, no warning.
    const n = c.applied.filteredByPrefix;
    return n > 0 ? `${n} finding${n === 1 ? "" : "s"} not shown (filtered by --only/--exclude).` : undefined;
  }
  const parts: string[] = [];
  if (c.applied.ruleOff > 0) parts.push(`${c.applied.ruleOff} by rules switched off`);
  if (c.applied.ignoredByPath > 0) parts.push(`${c.applied.ignoredByPath} by ignorePaths`);
  if (c.applied.filteredByPrefix > 0) parts.push(`${c.applied.filteredByPrefix} by --only/--exclude`);
  const extras: string[] = [];
  if (c.applied.severityOverridden > 0) {
    extras.push(`${c.applied.severityOverridden} severit${c.applied.severityOverridden === 1 ? "y" : "ies"} changed`);
  }
  if (known > 0) extras.push(`${known} marked known by baseline ${oneLine(c.baseline ?? "")} (never fail the run)`);
  if (relaxed) extras.push("failOn relaxed to critical");
  const source = c.source ? ` (policy from ${oneLine(c.source)})` : "";
  const head = `${hidden} finding${hidden === 1 ? "" : "s"} hidden${parts.length ? `: ${parts.join(", ")}` : ""}`;
  return `${head}${extras.length ? `; ${extras.join("; ")}` : ""}${source}. ` +
    "Review that policy if you did not write it — a repository can hide its own findings this way.";
}
