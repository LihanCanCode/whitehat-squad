import type { Finding, ScanReport } from "../core/types.js";
import { stripControl } from "../reporters/util.js";

export interface VerifyResult {
  readonly ruleId: string;
  readonly fixed: readonly Finding[];
  readonly stillPresent: readonly Finding[];
  readonly introduced: readonly Finding[];
}

/** Compares the last report with a fresh scan for one rule. */
export function compareRule(ruleId: string, before: ScanReport, after: ScanReport): VerifyResult {
  const wanted = (f: Finding): boolean => f.ruleId === ruleId;
  const oldFindings = before.findings.filter(wanted);
  const newFindings = after.findings.filter(wanted);
  const newIds = new Set(newFindings.map((f) => f.id));
  const oldIds = new Set(oldFindings.map((f) => f.id));
  return {
    ruleId,
    fixed: oldFindings.filter((f) => !newIds.has(f.id)),
    stillPresent: oldFindings.filter((f) => newIds.has(f.id)),
    introduced: newFindings.filter((f) => !oldIds.has(f.id)),
  };
}

/** Titles and paths come from scanned (untrusted) content: never print them raw. */
const clean = (text: string): string => stripControl(text).replace(/\n/g, " ");

const place = (f: Finding): string => {
  const e = f.evidence[0];
  return clean(e?.file ? `${e.file}${e.line ? `:${e.line}` : ""}` : (e?.url ?? ""));
};

export function formatVerify(result: VerifyResult): string {
  const lines = [`Verify ${clean(result.ruleId)}`];
  for (const f of result.fixed) lines.push(`  FIXED          ${clean(f.title)} (${place(f)})`);
  for (const f of result.stillPresent) lines.push(`  STILL PRESENT  ${clean(f.title)} (${place(f)})`);
  for (const f of result.introduced) lines.push(`  NEW            ${clean(f.title)} (${place(f)})`);
  if (lines.length === 1) lines.push("  Nothing to compare: this rule had no findings before or after.");
  const remaining = result.stillPresent.length + result.introduced.length;
  lines.push(remaining === 0 ? "Result: clean for this rule." : `Result: ${remaining} issue(s) remain.`);
  return lines.join("\n");
}

export function verifyExitIsClean(result: VerifyResult): boolean {
  return result.stillPresent.length + result.introduced.length === 0;
}
