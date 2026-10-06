import { describe, expect, it } from "vitest";
import { codeWindow, questionsFor, renderTriagePack } from "../../../src/remediation/triage.js";
import { finding, reportOf } from "./builders.js";

const FILE = Array.from({ length: 40 }, (_, i) => `line ${i + 1}`).join("\n");
const reader = (files: Record<string, string>) => async (p: string) => files[p] ?? null;

describe("codeWindow", () => {
  it("shows 8 lines either side and marks the evidence line", () => {
    const w = codeWindow(FILE, 20).split("\n");
    expect(w).toHaveLength(17);
    expect(w[0]).toContain("12 | line 12");
    expect(w[16]).toContain("28 | line 28");
    expect(w.filter((l) => l.startsWith(">"))).toEqual(["> 20 | line 20"]);
  });
  it("clamps at the start and end of the file", () => {
    expect(codeWindow(FILE, 2).split("\n")[0]).toContain(" 1 | line 1");
    expect(codeWindow(FILE, 40).split("\n").at(-1)).toContain("40 | line 40");
  });
  it("masks secret-shaped values and strips control characters", () => {
    const secret = ["sk", "live", "51H8abcDEF123ghiJKL456mnoPQR789stu"].join("_");
    const w = codeWindow(`a\nconst token = "${secret}";\nconst apiKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";\n\u001b[31mred`, 2);
    expect(w).not.toContain(secret);
    expect(w).not.toContain("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    expect(w).not.toContain("\u001b");
    expect(w).toContain("sk_l");
  });
  it("truncates very long lines", () => {
    expect(codeWindow("x".repeat(1000), 1).length).toBeLessThan(300);
  });
});

describe("questionsFor", () => {
  it.each([
    ["AUTH-002", "Is there an auth check in a middleware, wrapper or helper this handler goes through? Quote it."],
    ["PY-012", "Is there an auth check in a middleware"],
    ["DB-005", "Is there a later migration that changes this"],
    ["INJ-001", "Can the value actually be attacker-controlled here?"],
    ["PY-006", "Can the value actually be attacker-controlled here?"],
    ["AI-003", "Can the value actually be attacker-controlled here?"],
    ["SEC-090", "real credential, or a placeholder"],
    ["SUP-010", "really the one installed"],
    ["WEB-001", "mitigation elsewhere"],
  ])("%s gets a tailored first question", (rule, text) => {
    const qs = questionsFor(rule);
    expect(qs).toHaveLength(3);
    expect(qs[0]).toContain(text);
  });
});

describe("renderTriagePack", () => {
  const report = reportOf([
    finding({ id: "m1", ruleId: "AUTH-002", confidence: "medium", file: "src/a.ts", line: 20, title: "Unprotected route" }),
    finding({ id: "l1", ruleId: "DB-001", confidence: "low", file: "gone.sql", line: 3 }),
    finding({ id: "h1", ruleId: "AUTH-003", confidence: "high", file: "src/a.ts", line: 5 }),
    finding({ id: "s1", ruleId: "SEC-090", confidence: "low", file: "src/k.ts", line: 4 }),
    finding({ id: "e1", ruleId: "WEB-001", confidence: "medium", file: ".env.local", line: 1, baseline: true }),
    finding({ id: "u1", ruleId: "ZZZ-9", confidence: "low" }),
  ]);

  it("includes only low/medium findings with rule text, evidence and a code window", async () => {
    const pack = await renderTriagePack(report, reader({ "src/a.ts": FILE }));
    expect(pack).toContain("Unprotected route (AUTH-002, id m1)");
    expect(pack).not.toContain("id h1");
    expect(pack).toContain("What the rule says:");
    expect(pack).toContain("> 20 | line 20");
    expect(pack).toContain("1. Is there an auth check in a middleware, wrapper or helper this handler goes through? Quote it.");
    expect(pack).toContain("Is there a later migration that changes this");
    expect(pack).toContain("known (baseline)");
  });

  it("handles unreadable files, withheld credential windows and evidence-less findings", async () => {
    const pack = await renderTriagePack(report, reader({}));
    expect(pack).toContain("gone.sql:3: (file could not be read)");
    expect(pack).toContain("src/k.ts:4: (code window withheld");
    expect(pack).toContain(".env.local:1: (code window withheld");
    expect(pack).toContain("ZZZ-9");
  });

  it("de-duplicates repeated evidence locations", async () => {
    const f = finding({ id: "d", ruleId: "AUTH-002", confidence: "low", file: "src/a.ts", line: 20 });
    const doubled = { ...f, evidence: [...f.evidence, ...f.evidence, { url: "https://x.test/a", snippet: "s" }] };
    const pack = await renderTriagePack(reportOf([doubled]), reader({ "src/a.ts": FILE }));
    expect(pack.split("> 20 | line 20")).toHaveLength(2);
    expect(pack).toContain("https://x.test/a");
  });

  it("ends with the CONFIRMED / REJECTED / NEEDS-HUMAN instruction and forbids modifying code", async () => {
    const pack = await renderTriagePack(report, reader({}));
    for (const w of ["CONFIRMED", "REJECTED", "NEEDS-HUMAN", "Do NOT modify any code"]) expect(pack).toContain(w);
    expect(pack.trimEnd().endsWith("only for CONFIRMED findings.")).toBe(true);
  });

  it("says there is nothing to triage when every finding is high confidence", async () => {
    const pack = await renderTriagePack(reportOf([finding({ id: "h", ruleId: "AUTH-002" })]), reader({}));
    expect(pack).toContain("nothing to triage");
  });
});
