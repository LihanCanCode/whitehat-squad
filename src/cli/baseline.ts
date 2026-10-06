import { promises as fs } from "node:fs";
import { VERSION } from "../core/orchestrator.js";
import type { ScanReport } from "../core/types.js";
import { UsageError } from "./args.js";

export interface BaselineDoc {
  readonly schemaVersion: 1;
  readonly tool: "whitehat-squad";
  readonly toolVersion: string;
  readonly target: string;
  readonly findings: readonly { readonly id: string; readonly ruleId: string }[];
}

const MAX_BASELINE_BYTES = 10_000_000;

/** No timestamp and sorted ids, so a committed baseline only changes when the findings do. */
export function buildBaseline(report: ScanReport): BaselineDoc {
  const findings = report.findings
    .map((f) => ({ id: f.id, ruleId: f.ruleId }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { schemaVersion: 1, tool: "whitehat-squad", toolVersion: VERSION, target: report.target, findings };
}

export function parseBaseline(text: string, source: string): { readonly ids: ReadonlySet<string> } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new UsageError(`${source}: baseline is not valid JSON.`);
  }
  const findings = (raw as { findings?: unknown } | null)?.findings;
  if (typeof raw !== "object" || raw === null || !Array.isArray(findings)) {
    throw new UsageError(`${source}: not a whsquad baseline (expected a "findings" array).`);
  }
  const ids = new Set<string>();
  for (const f of findings as unknown[]) {
    const id = (f as { id?: unknown } | null)?.id;
    if (typeof id !== "string" || id === "") throw new UsageError(`${source}: every baseline finding needs a string "id".`);
    ids.add(id);
  }
  return { ids };
}

export async function loadBaselineIds(file: string): Promise<ReadonlySet<string>> {
  let text: string;
  try {
    const stat = await fs.stat(file);
    if (stat.size > MAX_BASELINE_BYTES) throw new UsageError(`${file}: baseline is larger than ${MAX_BASELINE_BYTES} bytes.`);
    text = await fs.readFile(file, "utf8");
  } catch (e) {
    if (e instanceof UsageError) throw e;
    throw new UsageError(`Cannot read baseline file "${file}". Create it with "whsquad baseline".`);
  }
  return parseBaseline(text, file).ids;
}
