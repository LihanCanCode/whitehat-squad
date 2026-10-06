import { describe, expect, it } from "vitest";
import { UsageError } from "../../../src/cli/args.js";
import { findRule, renderExplain, renderRules, selectRules } from "../../../src/cli/rules-cmd.js";
import { ALL_RULES, ruleHelpUri } from "../../../src/rules/catalog.js";

describe("selectRules", () => {
  it("returns the whole catalog without --agent", () => {
    expect(selectRules(undefined)).toEqual(ALL_RULES);
  });
  it("filters by agent id", () => {
    const rules = selectRules("auth-auditor");
    expect(rules.length).toBeGreaterThanOrEqual(7);
    expect(rules.every((r) => r.agent === "auth-auditor")).toBe(true);
  });
  it("rejects an unknown agent and lists the known ones", () => {
    expect(() => selectRules("nope")).toThrow(UsageError);
    expect(() => selectRules("nope")).toThrow(/auth-auditor/);
  });
});

describe("renderRules", () => {
  it("prints one aligned line per rule with id, severity, agent and title", () => {
    const text = renderRules(selectRules("recon"), "terminal");
    expect(text).toMatch(/RECON-L01\s+info\s+recon\s+Backend exposed to the browser/);
    expect(text.trim().split("\n")).toHaveLength(1 + 1); // header + one rule
  });
  it("prints valid JSON with the docs link per rule", () => {
    const parsed = JSON.parse(renderRules(selectRules("recon"), "json")) as { id: string; helpUri: string }[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.id).toBe("RECON-L01");
    expect(parsed[0]?.helpUri).toBe(ruleHelpUri("RECON-L01"));
  });
  it("says so when nothing matches", () => {
    expect(renderRules([], "terminal")).toContain("No rules");
    expect(JSON.parse(renderRules([], "json"))).toEqual([]);
  });
});

describe("findRule / renderExplain", () => {
  it("finds a rule case-insensitively", () => {
    expect(findRule("auth-002").id).toBe("AUTH-002");
  });
  it("throws a UsageError with near matches for an unknown id", () => {
    expect(() => findRule("AUTH-999")).toThrow(UsageError);
    expect(() => findRule("AUTH-999")).toThrow(/AUTH-002/);
    expect(() => findRule("ZZZ-1")).toThrow(/whsquad rules/);
  });
  it("explains what, why, how to fix, and where the docs are", () => {
    const text = renderExplain(findRule("AUTH-002"), "terminal");
    expect(text).toContain("AUTH-002");
    expect(text).toContain("CWE-306");
    expect(text).toContain("high");
    expect(text).toContain("How to fix");
    expect(text).toContain(ruleHelpUri("AUTH-002"));
    expect(text).toContain("whsquad-ignore AUTH-002");
  });
  it("explains as JSON", () => {
    const parsed = JSON.parse(renderExplain(findRule("AUTH-002"), "json")) as { id: string; fix: string };
    expect(parsed.id).toBe("AUTH-002");
    expect(parsed.fix.length).toBeGreaterThan(10);
  });
});
