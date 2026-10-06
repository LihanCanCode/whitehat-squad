import type { Finding, ScanReport } from "../core/types.js";

export interface ReportDiff {
  readonly newFindings: readonly Finding[];
  readonly fixedFindings: readonly Finding[];
}

/** Compares two scans by stable finding id. `prev === null` means this is the first scan. */
export function diffReports(prev: ScanReport | null, next: ScanReport): ReportDiff {
  const prevIds = new Set((prev?.findings ?? []).map((f) => f.id));
  const nextIds = new Set(next.findings.map((f) => f.id));
  return {
    newFindings: next.findings.filter((f) => !prevIds.has(f.id)),
    fixedFindings: (prev?.findings ?? []).filter((f) => !nextIds.has(f.id)),
  };
}

export interface BaselineSplit {
  readonly known: readonly Finding[];
  readonly fresh: readonly Finding[];
}

/** Splits a report into findings already in the baseline (by stable id) and new ones. */
export function knownFindings(baselineIds: ReadonlySet<string>, report: ScanReport): BaselineSplit {
  return {
    known: report.findings.filter((f) => baselineIds.has(f.id)),
    fresh: report.findings.filter((f) => !baselineIds.has(f.id)),
  };
}
