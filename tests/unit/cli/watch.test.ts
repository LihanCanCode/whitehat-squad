import { describe, expect, it, vi } from "vitest";
import { diffReports } from "../../../src/cli/diff.js";
import { runWatch } from "../../../src/cli/watch.js";
import { makeFinding } from "../../../src/core/finding.js";
import type { ScanReport } from "../../../src/core/types.js";

const f = (ruleId: string, snippet: string) =>
  makeFinding({
    ruleId, agentId: "a", title: `${ruleId} issue`, severity: "high", target: ".",
    explanation: "e", evidence: [{ file: "a.ts", line: 1, snippet }],
    fix: { summary: "s", agentPrompt: "p", references: [] },
  });

const report = (findings: ReturnType<typeof f>[]): ScanReport => ({
  schemaVersion: 1, tool: "whitehat-squad", version: "0.1.0", target: ".", mode: "static",
  startedAt: new Date().toISOString(), stack: { frameworks: [], backends: [], routes: [] },
  agents: [], findings,
});

describe("diffReports", () => {
  it("treats a null previous report as everything being new", () => {
    const diff = diffReports(null, report([f("SEC-001", "x")]));
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.fixedFindings).toHaveLength(0);
  });

  it("finds newly introduced and newly fixed findings by id", () => {
    const before = report([f("SEC-001", "x"), f("AUTH-002", "y")]);
    const after = report([f("SEC-001", "x"), f("WEB-003", "z")]);
    const diff = diffReports(before, after);
    expect(diff.newFindings.map((x) => x.ruleId)).toEqual(["WEB-003"]);
    expect(diff.fixedFindings.map((x) => x.ruleId)).toEqual(["AUTH-002"]);
  });

  it("reports no change when findings are identical", () => {
    const same = report([f("SEC-001", "x")]);
    const diff = diffReports(same, same);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.fixedFindings).toHaveLength(0);
  });
});

/** A scheduler that runs its callback immediately instead of after a real delay. */
function immediateSchedule(fn: () => void): { cancel: () => void } {
  fn();
  return { cancel: () => {} };
}

describe("runWatch", () => {
  it("prints the initial finding count on the first scan", async () => {
    const out = vi.fn();
    const scan = vi.fn().mockResolvedValue(report([f("SEC-001", "x")]));
    const stop = await runWatch(".", { scan, watch: () => () => {}, out, err: vi.fn() });
    expect(out).toHaveBeenCalledWith("Initial scan: 1 finding(s).");
    stop();
  });

  it("re-scans and prints only NEW/FIXED lines when a change comes in", async () => {
    const out = vi.fn();
    let call = 0;
    const scan = vi.fn().mockImplementation(async () => {
      call++;
      return call === 1 ? report([f("SEC-001", "x")]) : report([f("WEB-003", "y")]);
    });
    let trigger: () => void = () => {};
    const watch = (_root: string, onChange: () => void) => {
      trigger = onChange;
      return () => {};
    };
    const stop = await runWatch(".", { scan, watch, out, err: vi.fn(), schedule: immediateSchedule });
    trigger();
    await Promise.resolve();
    expect(out).toHaveBeenCalledWith(expect.stringContaining("FIXED  SEC-001"));
    expect(out).toHaveBeenCalledWith(expect.stringContaining("NEW    WEB-003"));
    stop();
  });

  it("prints 'no change' when a rescan finds the same issues", async () => {
    const out = vi.fn();
    const same = report([f("SEC-001", "x")]);
    const scan = vi.fn().mockResolvedValue(same);
    let trigger: () => void = () => {};
    const watch = (_root: string, onChange: () => void) => {
      trigger = onChange;
      return () => {};
    };
    const stop = await runWatch(".", { scan, watch, out, err: vi.fn(), schedule: immediateSchedule });
    trigger();
    await Promise.resolve();
    expect(out).toHaveBeenCalledWith("No change in findings.");
    stop();
  });

  it("reports a scan failure through err() instead of crashing", async () => {
    const err = vi.fn();
    const scan = vi.fn().mockRejectedValueOnce(new Error("boom")).mockResolvedValue(report([]));
    const stop = await runWatch(".", { scan, watch: () => () => {}, out: vi.fn(), err });
    expect(err).toHaveBeenCalledWith("Scan failed: boom");
    stop();
  });

  it("queues exactly one re-scan when changes arrive while a scan is still running, never overlapping", async () => {
    const out = vi.fn();
    let resolveFirst: (() => void) | undefined;
    let call = 0;
    const scan = vi.fn().mockImplementation(() => {
      call++;
      if (call === 2) return new Promise<ReturnType<typeof report>>((resolve) => (resolveFirst = () => resolve(report([f(`R${call}`, "x")]))));
      return Promise.resolve(report([f(`R${call}`, "x")]));
    });
    let trigger: () => void = () => {};
    const watch = (_root: string, onChange: () => void) => {
      trigger = onChange;
      return () => {};
    };
    const stop = await runWatch(".", { scan, watch, out, err: vi.fn(), schedule: immediateSchedule });
    trigger(); // starts scan #2
    trigger(); // fires while #2 is still pending -> must queue, not run concurrently
    trigger(); // same -> must collapse into the single queued run
    expect(scan).toHaveBeenCalledTimes(2); // initial + the one in-flight; none concurrent yet
    resolveFirst?.();
    await Promise.resolve();
    await Promise.resolve();
    expect(scan).toHaveBeenCalledTimes(3); // the collapsed queued run, not three extra runs
    stop();
  });

  it("stops both the timer and the underlying watcher when stopped", async () => {
    const stopWatching = vi.fn();
    const cancel = vi.fn();
    const schedule = () => ({ cancel });
    const scan = vi.fn().mockResolvedValue(report([]));
    let trigger: () => void = () => {};
    const watch = (_root: string, onChange: () => void) => {
      trigger = onChange;
      return stopWatching;
    };
    const stop = await runWatch(".", { scan, watch, out: vi.fn(), err: vi.fn(), schedule });
    trigger();
    stop();
    expect(cancel).toHaveBeenCalled();
    expect(stopWatching).toHaveBeenCalled();
  });
});
