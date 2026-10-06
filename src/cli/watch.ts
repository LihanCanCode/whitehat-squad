import type { ScanReport } from "../core/types.js";
import { diffReports } from "./diff.js";

export interface WatchDeps {
  readonly scan: () => Promise<ScanReport>;
  /** Calls onChange whenever the watched tree changes; returns a function that stops watching. */
  readonly watch: (root: string, onChange: () => void) => () => void;
  readonly out: (text: string) => void;
  readonly err: (text: string) => void;
  /** Overridable for tests; defaults to a real timer. */
  readonly schedule?: (fn: () => void, ms: number) => { cancel: () => void };
}

const DEBOUNCE_MS = 400;

function realSchedule(fn: () => void, ms: number): { cancel: () => void } {
  const handle = setTimeout(fn, ms);
  return { cancel: () => clearTimeout(handle) };
}

const place = (f: { evidence: readonly { file?: string; line?: number; url?: string }[] }): string => {
  const e = f.evidence[0];
  if (!e) return "";
  return e.file ? ` (${e.file}${e.line ? `:${e.line}` : ""})` : e.url ? ` (${e.url})` : "";
};

/**
 * Re-scans `root` on every change, debounced, and prints only what changed since the last scan.
 * Returns a function that stops watching. Scans never overlap: a change during a scan queues
 * exactly one more scan once the current one finishes, so rapid edits don't pile up concurrent runs.
 */
export async function runWatch(root: string, deps: WatchDeps): Promise<() => void> {
  const schedule = deps.schedule ?? realSchedule;
  let prev: ScanReport | null = null;
  let timer: { cancel: () => void } | null = null;
  let running = false;
  let pending = false;

  const scanOnce = async (): Promise<void> => {
    if (running) {
      pending = true;
      return;
    }
    running = true;
    try {
      const report = await deps.scan();
      if (prev === null) {
        deps.out(`Initial scan: ${report.findings.length} finding(s).`);
      } else {
        const diff = diffReports(prev, report);
        if (diff.newFindings.length === 0 && diff.fixedFindings.length === 0) {
          deps.out("No change in findings.");
        } else {
          for (const f of diff.fixedFindings) deps.out(`  FIXED  ${f.ruleId}  ${f.title}${place(f)}`);
          for (const f of diff.newFindings) deps.out(`  NEW    ${f.ruleId}  ${f.title}${place(f)}`);
        }
      }
      prev = report;
    } catch (e) {
      deps.err(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      running = false;
      if (pending) {
        pending = false;
        await scanOnce();
      }
    }
  };

  await scanOnce();

  const stopWatching = deps.watch(root, () => {
    timer?.cancel();
    timer = schedule(() => void scanOnce(), DEBOUNCE_MS);
  });

  return () => {
    timer?.cancel();
    stopWatching();
  };
}
