import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { createFsWatcher, isIgnoredPath } from "../../../src/cli/fs-watcher.js";
import { SKIP_DIRS } from "../../../src/core/fs-walk.js";

describe("isIgnoredPath", () => {
  it("ignores every directory the walker skips, at any depth and with either separator", () => {
    for (const dir of SKIP_DIRS) {
      expect(isIgnoredPath(`${dir}/x.ts`), dir).toBe(true);
      expect(isIgnoredPath(`pkg\\${dir}\\x.ts`), dir).toBe(true);
      expect(isIgnoredPath(dir), dir).toBe(true);
    }
  });
  it("does not ignore source files or look-alike names", () => {
    expect(isIgnoredPath("src/app.ts")).toBe(false);
    expect(isIgnoredPath("src/distance.ts")).toBe(false);
    expect(isIgnoredPath("my.node_modules.txt")).toBe(false);
  });
});

class FakeWatcher extends EventEmitter {
  closed = 0;
  close(): void {
    this.closed += 1;
  }
}

describe("createFsWatcher", () => {
  it("forwards changes but not changes under ignored directories", () => {
    const fake = new FakeWatcher();
    let listener: (e: string, f: string | null) => void = () => undefined;
    const onChange = vi.fn();
    createFsWatcher("root", onChange, {
      watchImpl: (_root, _opts, l) => {
        listener = l;
        return fake as never;
      },
    });
    listener("change", "src/a.ts");
    listener("change", ".next/cache/x");
    listener("change", "venv/lib/y.py");
    listener("change", null);
    expect(onChange).toHaveBeenCalledTimes(2);
  });

  it("reports a watcher error once, closes the watcher and does not throw", () => {
    const fake = new FakeWatcher();
    const onError = vi.fn();
    createFsWatcher("root", vi.fn(), { onError, watchImpl: () => fake as never });
    expect(() => fake.emit("error", new Error("EPERM: watch failed"))).not.toThrow();
    fake.emit("error", new Error("again"));
    expect(onError).toHaveBeenCalledTimes(1);
    expect(String(onError.mock.calls[0]?.[0])).toContain("EPERM");
    expect(fake.closed).toBe(1);
  });

  it("stop() closes the watcher exactly once even after an error", () => {
    const fake = new FakeWatcher();
    const stop = createFsWatcher("root", vi.fn(), { onError: vi.fn(), watchImpl: () => fake as never });
    fake.emit("error", new Error("x"));
    stop();
    expect(fake.closed).toBe(1);
  });

  it("falls back to non-recursive watching when recursive is unsupported", () => {
    const calls: boolean[] = [];
    const fake = new FakeWatcher();
    createFsWatcher("root", vi.fn(), {
      watchImpl: (_r, opts) => {
        calls.push(Boolean(opts.recursive));
        if (opts.recursive) throw new Error("ERR_FEATURE_UNAVAILABLE_ON_PLATFORM");
        return fake as never;
      },
    });
    expect(calls).toEqual([true, false]);
  });
});
