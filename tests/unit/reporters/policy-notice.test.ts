import { describe, expect, it } from "vitest";
import { policyNotice, renderTerminal } from "../../../src/reporters/terminal.js";
import type { ReportConfig } from "../../../src/core/types.js";
import { emptyReport } from "../../helpers/sample-report.js";

const config = (applied: Partial<ReportConfig["applied"]>, source = "whsquad.config.json"): ReportConfig => ({
  source,
  ignorePaths: [],
  rules: {},
  only: [],
  exclude: [],
  applied: { ignoredByPath: 0, ruleOff: 0, severityOverridden: 0, filteredByPrefix: 0, ...applied },
});

describe("policy notice (a repo hiding its own findings is never silent)", () => {
  it("says nothing when the policy changed nothing", () => {
    expect(policyNotice({ ...emptyReport(), config: config({}) })).toBeUndefined();
    expect(policyNotice(emptyReport())).toBeUndefined();
  });

  it("names every way findings were hidden and where the policy came from", () => {
    const notice = policyNotice({ ...emptyReport(), config: config({ ruleOff: 2, ignoredByPath: 1, severityOverridden: 3 }) });
    expect(notice).toContain("3 findings hidden");
    expect(notice).toContain("2 by rules switched off");
    expect(notice).toContain("1 by ignorePaths");
    expect(notice).toContain("3 severities changed");
    expect(notice).toContain("whsquad.config.json");
    expect(notice).toContain("Review that policy");
  });

  it("is printed in the terminal report, even when no findings remain", () => {
    const out = renderTerminal({ ...emptyReport(), config: config({ ruleOff: 1 }) }, { color: false });
    expect(out).toContain("1 finding hidden: 1 by rules switched off");
  });

  it("strips control characters from a hostile config path", () => {
    const notice = policyNotice({ ...emptyReport(), config: config({ ruleOff: 1 }, "evil\u001b[2J.json") });
    expect(notice).not.toContain("\u001b");
  });
});

// Security review: the notice must reach CI (SARIF) and PR text (markdown), not only the terminal.
describe("policy notice in every reporter", () => {
  it("is a SARIF tool-execution warning, plus a note for inline suppressions", async () => {
    const { renderSarif } = await import("../../../src/reporters/sarif.js");
    const sarif = JSON.parse(renderSarif({
      ...emptyReport(),
      config: config({ ruleOff: 2 }),
      suppressed: [{ id: "a", ruleId: "SEC-090" }],
    }));
    const notes = sarif.runs[0].invocations[0].toolExecutionNotifications;
    expect(notes.map((n: { level: string }) => n.level)).toEqual(["warning", "note"]);
    expect(notes[0].message.text).toContain("2 findings hidden");
  });

  it("is a warning line in markdown", async () => {
    const { renderMarkdown } = await import("../../../src/reporters/markdown.js");
    expect(renderMarkdown({ ...emptyReport(), config: config({ ignoredByPath: 1 }) })).toContain("**Warning:** 1 finding hidden");
  });

  it("counts findings a policy baseline marked as known, and a relaxed failOn", () => {
    const report = emptyReport();
    const known = { ...report, findings: [{ id: "k", ruleId: "AUTH-002", baseline: true }] } as unknown as typeof report;
    const notice = policyNotice({ ...known, config: { ...config({}), baseline: ".whsquad/baseline.json", failOn: "critical" } });
    expect(notice).toContain("1 marked known by baseline .whsquad/baseline.json");
    expect(notice).toContain("failOn relaxed to critical");
  });
});

describe("policy notice for the user's own filters", () => {
  it("states --only/--exclude filtering plainly, without the hostile-policy warning", () => {
    const notice = policyNotice({ ...emptyReport(), config: config({ filteredByPrefix: 9 }, undefined as unknown as string) });
    expect(notice).toBe("9 findings not shown (filtered by --only/--exclude).");
  });
  it("still warns when a config file also hid findings", () => {
    expect(policyNotice({ ...emptyReport(), config: config({ filteredByPrefix: 2, ruleOff: 1 }) })).toContain("Review that policy");
  });
});

describe("wrapToWidth", () => {
  it("wraps at word boundaries with a hanging indent and ignores ANSI when measuring", async () => {
    const { wrapToWidth } = await import("../../../src/reporters/wrap.js");
    const out = wrapToWidth("  \u001b[31mfix:\u001b[0m rotate the exposed key at the provider dashboard now", 24);
    expect(out.split("\n").every((l) => l.replace(/\u001b\[[0-9;]*m/g, "").length <= 24)).toBe(true);
    expect(out).toContain("\n    ");
    expect(out.replace(/\n\s+/g, " ")).toContain("rotate the exposed key at the provider dashboard now");
  });
  it("leaves text alone without a usable width, and stops at a marker line", async () => {
    const { wrapToWidth } = await import("../../../src/reporters/wrap.js");
    const long = "x ".repeat(40).trim();
    expect(wrapToWidth(long, undefined)).toBe(long);
    expect(wrapToWidth(long, 10)).toBe(long);
    expect(wrapToWidth(`a\nSQL:\n${long}`, 30, "SQL:")).toBe(`a\nSQL:\n${long}`);
  });
});

describe("paintStatus", () => {
  it("colours FIXED green and NEW / STILL PRESENT red only when colour is on", async () => {
    const { paintStatus } = await import("../../../src/reporters/wrap.js");
    const text = "Verify DB-001\n  FIXED          a\n  STILL PRESENT  b\n  NEW    c";
    expect(paintStatus(text, false)).toBe(text);
    const on = paintStatus(text, true);
    expect(on).toContain("\u001b[1;32mFIXED\u001b[0m");
    expect(on).toContain("\u001b[1;31mSTILL PRESENT\u001b[0m");
    expect(on).toContain("\u001b[1;31mNEW\u001b[0m");
    expect(on.split("\n")[0]).toBe("Verify DB-001");
  });
});
