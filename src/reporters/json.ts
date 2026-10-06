import type { ScanReport } from "../core/types.js";

export function renderJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2) + "\n";
}
