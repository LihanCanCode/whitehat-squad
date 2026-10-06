import { describe, expect, it } from "vitest";
import { compareVersions, exactVersion, satisfies } from "../../../src/agents/supply-chain/semver.js";

describe("compareVersions", () => {
  it("orders numeric parts numerically, not lexically", () => {
    expect(compareVersions("1.2.3", "1.2.4")).toBeLessThan(0);
    expect(compareVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareVersions("2.0.0", "2.0.0")).toBe(0);
  });
  it("ranks a prerelease below its release", () => {
    expect(compareVersions("1.0.0-canary.1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("15.2.0-canary.0", "15.1.9")).toBeGreaterThan(0);
  });
  it("compares prerelease identifiers per the semver spec", () => {
    expect(compareVersions("1.0.0-canary.10", "1.0.0-canary.9")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0-alpha", "1.0.0-alpha.1")).toBeLessThan(0);
    expect(compareVersions("1.0.0-1", "1.0.0-alpha")).toBeLessThan(0);
    expect(compareVersions("1.0.0-alpha", "1.0.0-beta")).toBeLessThan(0);
  });
  it("handles hyphenated prerelease identifiers (react canary builds)", () => {
    expect(compareVersions("19.2.0-canary-63779030-20250328", "19.2.0-canary-63779030-20250328")).toBe(0);
    expect(compareVersions("19.2.0-canary-63779030-20250328", "19.2.0")).toBeLessThan(0);
  });
  it("ignores build metadata and a leading v or =", () => {
    expect(compareVersions("1.0.0+build.5", "1.0.0")).toBe(0);
    expect(compareVersions("v1.0.0", "=1.0.0")).toBe(0);
  });
  it("returns null for unparseable versions", () => {
    expect(compareVersions("1.x", "1.0.0")).toBeNull();
    expect(compareVersions("", "1.0.0")).toBeNull();
    expect(compareVersions("latest", "1.0.0")).toBeNull();
  });
});

describe("satisfies (GitHub advisory range syntax)", () => {
  it("evaluates a closed interval", () => {
    expect(satisfies("13.0.0", ">= 13.0.0, < 13.5.9")).toBe(true);
    expect(satisfies("13.5.8", ">= 13.0.0, < 13.5.9")).toBe(true);
    expect(satisfies("13.5.9", ">= 13.0.0, < 13.5.9")).toBe(false);
    expect(satisfies("12.9.9", ">= 13.0.0, < 13.5.9")).toBe(false);
  });
  it("tolerates missing spaces", () => {
    expect(satisfies("14.1.0", ">=14.0.0,<14.2.25")).toBe(true);
    expect(satisfies("14.1.0", ">= 14.0.0 , < 14.2.25")).toBe(true);
  });
  it("supports = and single comparators", () => {
    expect(satisfies("19.2.0", "= 19.2.0")).toBe(true);
    expect(satisfies("19.2.1", "= 19.2.0")).toBe(false);
    expect(satisfies("19.2.1", "<= 19.2.1")).toBe(true);
    expect(satisfies("2.0.0", "> 1.9.9")).toBe(true);
  });
  it("uses plain ordering for prereleases, like GitHub's database", () => {
    const r = ">= 15.2.0-canary.0, < 15.2.6";
    expect(satisfies("15.2.0-canary.5", r)).toBe(true);
    expect(satisfies("15.2.0", r)).toBe(true);
    expect(satisfies("15.2.5", r)).toBe(true);
    expect(satisfies("15.2.6", r)).toBe(false);
    expect(satisfies("15.2.6-canary.1", r)).toBe(true);
    expect(satisfies("15.1.9", r)).toBe(false);
    expect(satisfies("15.1.9-canary.99", r)).toBe(false);
  });
  it("is false for malformed ranges or versions, never throws", () => {
    expect(satisfies("1.0.0", "")).toBe(false);
    expect(satisfies("1.0.0", "garbage")).toBe(false);
    expect(satisfies("nope", ">= 1.0.0")).toBe(false);
    expect(satisfies("1.0.0", ">= 1.0.0, < ")).toBe(false);
  });
});

describe("exactVersion", () => {
  it("accepts only exactly pinned specs", () => {
    expect(exactVersion("5.6.1")).toBe("5.6.1");
    expect(exactVersion("=5.6.1")).toBe("5.6.1");
    expect(exactVersion("v5.6.1")).toBe("5.6.1");
    expect(exactVersion(" 1.0.0-beta.1 ")).toBe("1.0.0-beta.1");
  });
  it("rejects ranges, tags and aliases", () => {
    for (const s of ["^5.6.1", "~5.6.1", ">=1.0.0", "1.x", "*", "latest", "npm:foo@1.0.0", "1.2", ">=1.0.0 <2.0.0", ""]) {
      expect(exactVersion(s)).toBeNull();
    }
  });
});
