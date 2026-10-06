import { describe, expect, it } from "vitest";
import { makeFinding } from "../../src/core/finding.js";
import { runScan } from "../../src/core/orchestrator.js";
import { normalizePrefixes, resolveOverride } from "../../src/core/policy.js";
import type { Agent, Finding, Severity } from "../../src/core/types.js";
import { memFiles } from "../helpers/memfs.js";

function finding(ruleId: string, file: string, severity: Severity = "high", snippet = "s"): Finding {
  return makeFinding({
    ruleId, agentId: "t", title: `t ${ruleId}`, severity, target: ".", explanation: "e",
    evidence: [{ file, line: 1, snippet }],
    fix: { summary: "s", agentPrompt: "p", references: [] },
  });
}

const agent = (...f: Finding[]): Agent => ({ id: "t", name: "t", role: "r", modes: ["static"], run: async () => f });
const scan = (policy: Parameters<typeof runScan>[0]["policy"], ...f: Finding[]) =>
  runScan({ mode: "static", targetLabel: ".", files: memFiles({}), agents: [agent(...f)], ...(policy ? { policy } : {}) });

describe("resolveOverride", () => {
  it("prefers an exact id over a wildcard and the longest wildcard over a shorter one", () => {
    const rules = { "DB-*": "low", "DB-0*": "medium", "DB-001": "off" } as const;
    expect(resolveOverride(rules, "DB-001")).toBe("off");
    expect(resolveOverride(rules, "DB-002")).toBe("medium");
    expect(resolveOverride(rules, "DB-L01")).toBe("low");
    expect(resolveOverride(rules, "SEC-001")).toBeUndefined();
  });
});

describe("normalizePrefixes", () => {
  it("upper-cases, trims and drops empty entries", () => {
    expect(normalizePrefixes(" db, sec-1 ,,")).toEqual(["DB", "SEC-1"]);
    expect(normalizePrefixes(undefined)).toEqual([]);
  });
});

describe("scan policy", () => {
  const fs = [finding("DB-001", "a.ts"), finding("SEC-100", "b.ts"), finding("SEC-010", "c.ts"), finding("AUTH-002", "d.ts")];

  it("--only keeps matching prefixes", async () => {
    const r = await scan({ only: ["DB", "SEC-1"] }, ...fs);
    expect(r.findings.map((f) => f.ruleId).sort()).toEqual(["DB-001", "SEC-100"]);
    expect(r.config?.only).toEqual(["DB", "SEC-1"]);
    expect(r.config?.applied.filteredByPrefix).toBe(2);
  });

  it("--exclude drops matching prefixes", async () => {
    const r = await scan({ exclude: ["SEC"] }, ...fs);
    expect(r.findings.map((f) => f.ruleId).sort()).toEqual(["AUTH-002", "DB-001"]);
  });

  it("rules: off removes findings and severity overrides change severity", async () => {
    const r = await scan({ rules: { "SEC-*": "off", "DB-001": "low" } }, ...fs);
    expect(r.findings.map((f) => `${f.ruleId}:${f.severity}`).sort()).toEqual(["AUTH-002:high", "DB-001:low"]);
    expect(r.config?.applied).toMatchObject({ ruleOff: 2, severityOverridden: 1 });
    expect(r.config?.rules).toEqual({ "SEC-*": "off", "DB-001": "low" });
  });

  it("ignorePaths drops findings whose evidence files all match (gitignore-style globs)", async () => {
    const r = await scan({ ignorePaths: ["docs/", "*.fixture.ts"] }, finding("DB-001", "docs/a.ts"), finding("DB-002", "x/y.fixture.ts"), finding("DB-003", "src/ok.ts"));
    expect(r.findings.map((f) => f.ruleId)).toEqual(["DB-003"]);
    expect(r.config?.applied.ignoredByPath).toBe(2);
  });

  it("marks baseline ids as known without removing them", async () => {
    const known = finding("DB-001", "a.ts");
    const r = await scan({ baselineIds: new Set([known.id]) }, known, finding("DB-002", "b.ts"));
    expect(r.findings.find((f) => f.ruleId === "DB-001")?.baseline).toBe(true);
    expect(r.findings.find((f) => f.ruleId === "DB-002")?.baseline).toBeUndefined();
  });

  it("omits config when no policy is given", async () => {
    const r = await scan(undefined, finding("DB-001", "a.ts"));
    expect(r.config).toBeUndefined();
  });
});
