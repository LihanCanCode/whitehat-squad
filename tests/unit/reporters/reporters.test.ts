import { afterEach, describe, expect, it } from "vitest";
import { isReportFormat, renderReport } from "../../../src/reporters/index.js";
import { renderMarkdown } from "../../../src/reporters/markdown.js";
import { renderTerminal } from "../../../src/reporters/terminal.js";
import { renderSarif } from "../../../src/reporters/sarif.js";
import { renderJson } from "../../../src/reporters/json.js";
import { emptyReport, sampleFinding, sampleReport } from "../../helpers/sample-report.js";

const ESC = String.fromCharCode(27);

describe("index", () => {
  it("validates formats", () => {
    expect(isReportFormat("sarif")).toBe(true);
    expect(isReportFormat("terminal")).toBe(true);
    expect(isReportFormat("json")).toBe(true);
    expect(isReportFormat("markdown")).toBe(true);
    expect(isReportFormat("xml")).toBe(false);
    expect(isReportFormat("")).toBe(false);
  });
  it("dispatches to every renderer deterministically", () => {
    const r = sampleReport();
    for (const f of ["terminal", "json", "sarif", "markdown"] as const) {
      const a = renderReport(r, f, { color: false });
      expect(a.length).toBeGreaterThan(0);
      expect(renderReport(r, f, { color: false })).toBe(a);
    }
  });
});

describe("json", () => {
  it("round-trips", () => {
    const r = sampleReport();
    const out = renderJson(r);
    expect(JSON.parse(out)).toEqual(JSON.parse(JSON.stringify(r)));
    expect(JSON.parse(out).schemaVersion).toBe(1);
    expect(out).toContain("\n  ");
  });
});

describe("sarif", () => {
  const doc = JSON.parse(renderSarif(sampleReport()));
  const run = doc.runs[0];

  it("has SARIF 2.1.0 envelope", () => {
    expect(doc.version).toBe("2.1.0");
    expect(doc.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(doc.runs).toHaveLength(1);
    expect(run.tool.driver.name).toBe("whitehat-squad");
    expect(run.tool.driver.version).toBe("0.1.0");
    expect(run.tool.driver.informationUri).toBe("https://github.com/LihanCanCode/whitehat-squad");
  });
  it("derives unique rules", () => {
    const ids = run.tool.driver.rules.map((x: { id: string }) => x.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain("supabase/rls-disabled");
    const rule = run.tool.driver.rules.find((x: { id: string }) => x.id === "secrets/stripe-live-key");
    expect(rule.shortDescription.text).toBe("Live Stripe key committed");
    expect(rule.help.text).toContain("rotate");
    expect(rule.defaultConfiguration.level).toBe("error");
    expect(rule.properties.tags).toContain("CWE-798");
  });
  it("maps levels", () => {
    const lv = (id: string) => run.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === id).level;
    expect(lv("abc123def456")).toBe("error");
    expect(lv("id-high-1")).toBe("error");
    expect(lv("id-med")).toBe("warning");
    expect(lv("id-low")).toBe("note");
    expect(lv("id-info")).toBe("note");
  });
  it("emits relative posix uris and regions", () => {
    const res = run.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === "abc123def456");
    const loc = res.locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe("src/lib/pay.ts");
    expect(loc.region.startLine).toBe(12);
    expect(res.message.text).toContain("Live Stripe key committed");
    expect(res.properties).toEqual({ severity: "critical", confidence: "high", agent: "secret-hunter" });
    const win = run.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === "id-high-2");
    expect(win.locations[0].physicalLocation.artifactLocation.uri).toBe("db/schema.sql");
  });
  it("uses url for live evidence and no locations when no evidence", () => {
    const live = run.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === "id-high-1");
    expect(live.locations[0].physicalLocation.artifactLocation.uri).toBe("https://app.example.com/rest/v1/users");
    const none = run.results.find((x: { partialFingerprints: Record<string, string> }) => x.partialFingerprints["whsquadFinding/v1"] === "id-med");
    expect(none.locations ?? []).toEqual([]);
  });
  it("strips leading slashes, drive letters and dot segments", () => {
    const r = sampleReport({
      findings: [
        sampleFinding({ id: "a", evidence: [{ file: "/abs/x.ts", line: 1, snippet: "" }] }),
        sampleFinding({ id: "b", evidence: [{ file: "./y.ts", snippet: "" }] }),
        sampleFinding({ id: "c", evidence: [{ file: "C:\\proj\\z.ts", line: 0, snippet: "" }] }),
      ],
    });
    const res = JSON.parse(renderSarif(r)).runs[0].results;
    expect(res[0].locations[0].physicalLocation.artifactLocation.uri).toBe("abs/x.ts");
    expect(res[1].locations[0].physicalLocation.artifactLocation.uri).toBe("y.ts");
    expect(res[1].locations[0].physicalLocation).not.toHaveProperty("region");
    expect(res[2].locations[0].physicalLocation.artifactLocation.uri).toBe("proj/z.ts");
    expect(res[2].locations[0].physicalLocation).not.toHaveProperty("region");
  });
  it("handles empty report", () => {
    const d = JSON.parse(renderSarif(emptyReport()));
    expect(d.runs[0].results).toEqual([]);
    expect(d.runs[0].tool.driver.rules).toEqual([]);
  });
  it("omits cwe tag when absent", () => {
    const f = sampleFinding();
    const { cwe: _c, ...rest } = f;
    const d = JSON.parse(renderSarif(sampleReport({ findings: [rest] })));
    expect(d.runs[0].tool.driver.rules[0].properties.tags).not.toContain("CWE-798");
  });
});

describe("markdown", () => {
  const md = renderMarkdown(sampleReport());
  it("has title, summary table, roster, finding sections", () => {
    expect(md).toMatch(/^# /);
    expect(md).toContain("| Severity | Count |");
    expect(md).toContain("| Critical | 1 |");
    expect(md).toContain("| High | 2 |");
    expect(md).toContain("Squad roster");
    expect(md).toContain("Secret Hunter");
    expect(md).toContain("timeout talking to db");
    expect(md).toContain("Live Stripe key committed");
    expect(md).toContain("secrets/stripe-live-key");
    expect(md).toContain("src/lib/pay.ts:12");
    expect(md).toContain("How to fix");
    expect(md).toContain("```sql");
    expect(md).toContain("```diff");
    expect(md).toContain("Paste this into your coding agent");
    expect(md).toContain("Remove the hardcoded Stripe key");
    expect(md).toContain("whsquad verify secrets/stripe-live-key .");
  });
  it("uses a longer fence than any backtick run in a snippet", () => {
    const evil = "x\n```\n# injected <script>alert(1)</script>\n````\n";
    const out = renderMarkdown(
      sampleReport({ findings: [sampleFinding({ evidence: [{ file: "a.ts", line: 1, snippet: evil }] })] }),
    );
    expect(out).toContain("`````\nx\n```\n# injected");
    const idx = out.indexOf("`````\nx");
    expect(idx).toBeGreaterThan(-1);
    const closeIdx = out.indexOf("\n`````\n", idx + 5);
    expect(closeIdx).toBeGreaterThan(idx + evil.length - 2);
  });
  it("neutralises html/markdown in titles and explanations", () => {
    const out = renderMarkdown(
      sampleReport({
        findings: [sampleFinding({ title: "<img src=x onerror=alert(1)>", explanation: "see [a](javascript:x) <b>hi</b>" })],
      }),
    );
    expect(out).not.toContain("<img");
    expect(out).not.toContain("<b>");
    expect(out).toContain("&lt;img");
  });
  it("renders empty report", () => {
    const out = renderMarkdown(emptyReport());
    expect(out).toContain("No findings");
    expect(out).toContain("not proof of security");
  });
  it("handles findings without optional fix parts or evidence", () => {
    const f = sampleFinding({ evidence: [{ url: "https://x.test/a", snippet: "" }] });
    const bare = { ...f, fix: { summary: "s", agentPrompt: "p", references: [] } };
    const out = renderMarkdown(sampleReport({ findings: [bare] }));
    expect(out).toContain("https://x.test/a");
    expect(out).not.toContain("```sql");
  });
  it("lists references and an evidence entry with neither file nor url", () => {
    const f = sampleFinding({ evidence: [{ snippet: "bare" }] });
    const out = renderMarkdown(sampleReport({ findings: [f] }));
    expect(out).toContain("https://stripe.com/docs/keys");
    expect(out).toContain("bare");
  });
});

describe("terminal", () => {
  afterEach(() => {
    delete process.env["NO_COLOR"];
  });
  it("emits no ANSI when color is false", () => {
    const out = renderTerminal(sampleReport(), { color: false });
    expect(out).not.toContain(ESC);
    expect(out).toContain("Live Stripe key committed");
    expect(out).toContain("fix:");
    expect(out).toContain("secrets/stripe-live-key");
    expect(out).toContain("src/lib/pay.ts:12");
    expect(out).toContain("6 findings (1 critical, 2 high, 1 medium, 1 low, 1 info)");
    expect(out).toContain("./my-app");
    expect(out).toContain("static");
    expect(out).toContain("next");
    expect(out).toContain("timeout talking to db");
  });
  it("colors by severity when enabled", () => {
    const out = renderTerminal(sampleReport(), { color: true });
    expect(out).toContain(ESC + "[");
    expect(out).toContain(ESC + "[1;31m"); // critical red bold
    expect(out).toContain(ESC + "[33m"); // medium yellow
    expect(out).toContain(ESC + "[36m"); // low cyan
    expect(out).toContain(ESC + "[2m"); // info dim
  });
  it("honors NO_COLOR", () => {
    process.env["NO_COLOR"] = "1";
    expect(renderTerminal(sampleReport(), { color: true })).not.toContain(ESC);
  });
  it("honors FORCE_COLOR for piped output, but NO_COLOR and an explicit --no-color win", () => {
    try {
      process.env["FORCE_COLOR"] = "1";
      expect(renderTerminal(sampleReport())).toContain(ESC);
      expect(renderTerminal(sampleReport(), { color: false })).not.toContain(ESC);
      process.env["NO_COLOR"] = "1";
      expect(renderTerminal(sampleReport())).not.toContain(ESC);
      delete process.env["NO_COLOR"];
      process.env["FORCE_COLOR"] = "0";
      expect(renderTerminal(sampleReport())).toBe(renderTerminal(sampleReport(), { color: Boolean(process.stdout.isTTY) }));
    } finally {
      delete process.env["FORCE_COLOR"];
    }
  });
  it("orders critical before info", () => {
    const out = renderTerminal(sampleReport(), { color: false });
    expect(out.indexOf("Live Stripe key")).toBeLessThan(out.indexOf("Stack detected"));
  });
  it("strips hostile escape sequences and control chars from content", () => {
    const hostile = `a${ESC}[31mRED${ESC}]0;pwned\u0007b\u0000c\r\nd\u009b2J`;
    const out = renderTerminal(
      sampleReport({
        findings: [
          sampleFinding({
            title: `T${ESC}[2Jitle`,
            explanation: hostile,
            evidence: [{ file: `f${ESC}[0m.ts`, line: 1, snippet: hostile }],
          }),
        ],
      }),
      { color: false },
    );
    expect(out).not.toContain(ESC);
    expect(out).not.toContain("\u0007");
    expect(out).not.toContain("\u0000");
    expect(out).not.toContain("\u009b");
    expect(out).not.toContain("\r");
  });
  it("prints a friendly empty message", () => {
    const out = renderTerminal(emptyReport(), { color: false });
    expect(out).toContain("No findings - nice work. Remember: absence of findings is not proof of security.");
    expect(out).toContain("0 findings");
  });
  it("singularises one finding and handles url/no evidence", () => {
    const out = renderTerminal(
      sampleReport({ findings: [sampleFinding({ evidence: [{ url: "https://x.test/", snippet: "s" }] })] }),
      { color: false },
    );
    expect(out).toContain("1 finding (1 critical");
    expect(out).toContain("https://x.test/");
  });
  it("is deterministic and defaults color from options", () => {
    const r = sampleReport();
    expect(renderTerminal(r, { color: true })).toBe(renderTerminal(r, { color: true }));
    expect(renderTerminal(r)).toBe(renderTerminal(r, {}));
  });
});
