import { describe, expect, it } from "vitest";
import { HELP, parseCli, UsageError } from "../../../src/cli/args.js";

describe("parseCli: existing flags keep their defaults", () => {
  it("defaults failOn to high and marks it as not explicit", () => {
    const { options } = parseCli(["scan", "."]);
    expect(options.failOn).toBe("high");
    expect(options.failOnExplicit).toBe(false);
    expect(options.maxRequests).toBe(100);
    expect(options.only).toEqual([]);
    expect(options.exclude).toEqual([]);
    expect(options.baseline).toBeUndefined();
  });
  it("marks an explicit --fail-on", () => {
    const { options } = parseCli(["scan", ".", "--fail-on", "medium"]);
    expect(options.failOn).toBe("medium");
    expect(options.failOnExplicit).toBe(true);
  });
});

describe("parseCli: new flags", () => {
  it("parses --only and --exclude as upper-cased prefix lists", () => {
    const { options } = parseCli(["scan", ".", "--only", "db,sec-1", "--exclude", "WEB, SUP-00"]);
    expect(options.only).toEqual(["DB", "SEC-1"]);
    expect(options.exclude).toEqual(["WEB", "SUP-00"]);
  });
  it.each(["DB*", "db;rm", "1B", "SEC--1"])("rejects the malformed prefix %s", (bad) => {
    expect(() => parseCli(["scan", ".", "--only", bad])).toThrow(UsageError);
  });
  it("parses --baseline, --agent, --show-suppressed", () => {
    const { options } = parseCli(["scan", ".", "--baseline", "b.json", "--agent", "database-guard", "--show-suppressed"]);
    expect(options.baseline).toBe("b.json");
    expect(options.agent).toBe("database-guard");
    expect(options.showSuppressed).toBe(true);
  });
  it("parses --max-requests and rejects non-integers and out-of-range values", () => {
    expect(parseCli(["scan", "https://x.test", "--max-requests", "40"]).options.maxRequests).toBe(40);
    for (const bad of ["0", "-3", "abc", "1.5", "100000"]) {
      expect(() => parseCli(["scan", ".", "--max-requests", bad])).toThrow(UsageError);
    }
  });
  it("passes rules and explain through as commands", () => {
    expect(parseCli(["rules", "--format", "json"]).command).toBe("rules");
    expect(parseCli(["explain", "DB-001"]).positionals).toEqual(["DB-001"]);
    expect(parseCli(["baseline", "app"]).command).toBe("baseline");
  });
});

describe("HELP", () => {
  it("documents every new command and flag", () => {
    for (const word of ["rules", "explain", "baseline", "--only", "--exclude", "--baseline", "--max-requests", "--agent", "whsquad.config.json", "whsquad-ignore"]) {
      expect(HELP, word).toContain(word);
    }
  });
});
