import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../../src/cli/main.js";
import type { ScanReport } from "../../src/core/types.js";
import { makeTempDir, writeTree } from "../helpers/sample-apps.js";

/** A small app whose findings come from the auth-auditor and ai-guard agents (owned by this wave). */
const APP: Record<string, string> = {
  "package.json": JSON.stringify({
    name: "demo",
    dependencies: { next: "14.2.0", react: "18.3.0", "@supabase/supabase-js": "2.45.0", openai: "4.60.0" },
  }),
  "src/app/api/notes/[id]/route.ts":
    'export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n' +
    '  await supabase.from("notes").delete().eq("id", params.id);\n' +
    "  return Response.json({ ok: true });\n}\n",
  "next.config.js": "module.exports = {\n  productionBrowserSourceMaps: true,\n};\n",
  "src/components/Chat.tsx":
    '"use client";\nimport OpenAI from "openai";\n' +
    "const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });\n" +
    "export default function Chat() { return null; }\n",
};

let stdout = "";
let stderr = "";

describe("CLI features", () => {
  let dir: string;
  let previousCwd: string;
  beforeEach(async () => {
    dir = await makeTempDir();
    previousCwd = process.cwd();
    process.chdir(dir);
    stdout = "";
    stderr = "";
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      stdout += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr += String(chunk);
      return true;
    });
    await writeTree(path.join(dir, "app"), APP);
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.chdir(previousCwd);
    await fs.rm(dir, { recursive: true, force: true });
  });

  /** Scan to JSON, return exit code and report. */
  async function scan(...args: string[]): Promise<{ code: number; report: ScanReport }> {
    const out = path.join(dir, `r-${Math.random().toString(36).slice(2)}.json`);
    const code = await main(["scan", ...args, "--format", "json", "--out", out]);
    return { code, report: JSON.parse(await fs.readFile(out, "utf8")) as ScanReport };
  }
  const rules = (r: ScanReport): string[] => r.findings.map((f) => f.ruleId);

  describe("rules and explain", () => {
    it("lists rules, filters by agent, and prints JSON", async () => {
      expect(await main(["rules"])).toBe(0);
      expect(stdout).toContain("AUTH-002");
      expect(stdout).toContain("WEB-L11");
      stdout = "";
      expect(await main(["rules", "--agent", "ai-guard", "--format", "json"])).toBe(0);
      const parsed = JSON.parse(stdout) as { id: string; agent: string }[];
      expect(parsed.length).toBeGreaterThanOrEqual(7);
      expect(parsed.every((r) => r.agent === "ai-guard")).toBe(true);
    });
    it("explains a rule and rejects unknown ones with exit 2", async () => {
      expect(await main(["explain", "auth-003"])).toBe(0);
      expect(stdout).toContain("AUTH-003");
      expect(stdout).toContain("How to fix");
      expect(await main(["explain", "NOPE-1"])).toBe(2);
      expect(await main(["explain"])).toBe(2);
      expect(await main(["rules", "--agent", "bogus"])).toBe(2);
    });
  });

  describe("suppression", () => {
    // Suppression is central (no agent filters its own findings), so one agent proves it for all.
    it("hides a web-hardener finding with a whsquad-ignore comment on its line and lists it in the report", async () => {
      const first = await scan("app", "--only", "WEB-001");
      expect(rules(first.report)).toEqual(["WEB-001"]);
      const config = path.join(dir, "app/next.config.js");
      await fs.writeFile(
        config,
        "module.exports = {\n  productionBrowserSourceMaps: true, // whsquad-ignore WEB-001 -- needed for Sentry\n};\n",
      );
      const second = await scan("app", "--only", "WEB-001");
      expect(second.report.findings).toEqual([]);
      expect(second.report.suppressed).toEqual([
        expect.objectContaining({ ruleId: "WEB-001", file: "next.config.js", line: 2, reason: "needed for Sentry" }),
      ]);
    });

    it("honours the directive on the line above, with a wildcard and any comment syntax", async () => {
      await fs.writeFile(
        path.join(dir, "app/next.config.js"),
        "module.exports = {\n  /* whsquad-ignore WEB-* */\n  productionBrowserSourceMaps: true,\n};\n",
      );
      const { report } = await scan("app", "--only", "WEB-001");
      expect(report.findings).toEqual([]);
      expect(report.suppressed).toHaveLength(1);
    });

    it("lists suppressed findings in the terminal report with --show-suppressed", async () => {
      await fs.writeFile(
        path.join(dir, "app/next.config.js"),
        "module.exports = {\n  productionBrowserSourceMaps: true, // whsquad-ignore WEB-001 -- why\n};\n",
      );
      await main(["scan", "app", "--only", "WEB-001", "--no-color", "--show-suppressed"]);
      expect(stdout).toContain("WEB-001 next.config.js:2 -- why");
    });
  });

  describe("config file", () => {
    it("turns rules off and records what it did", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ rules: { "AI-*": "off" } }));
      const { report } = await scan("app", "--only", "AI,AUTH");
      expect(rules(report).some((r) => r.startsWith("AI-"))).toBe(false);
      expect(rules(report)).toContain("AUTH-003");
      expect(report.config?.rules).toEqual({ "AI-*": "off" });
      expect(report.config?.applied.ruleOff).toBeGreaterThan(0);
      expect(report.config?.source).toMatch(/whsquad\.config\.json$/);
    });

    it("overrides severity, so failOn decides the exit code", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ rules: { "AUTH-*": "low" } }));
      const { code, report } = await scan("app", "--only", "AUTH");
      expect(report.findings.length).toBeGreaterThan(0);
      expect(report.findings.every((f) => f.severity === "low")).toBe(true);
      expect(code).toBe(0);
    });

    it("ignorePaths drops findings in matching files", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ ignorePaths: ["src/components/"] }));
      const { report } = await scan("app", "--only", "AI");
      expect(report.findings).toEqual([]);
      expect(report.config?.applied.ignoredByPath).toBeGreaterThan(0);
    });

    it("failOn from the config is used unless --fail-on is passed", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ failOn: "critical" }));
      const viaConfig = await scan("app", "--only", "AUTH-003");
      expect(viaConfig.report.findings.length).toBeGreaterThan(0);
      expect(viaConfig.code).toBe(0);
      const viaFlag = await scan("app", "--only", "AUTH-003", "--fail-on", "high");
      expect(viaFlag.code).toBe(1);
    });

    it("rejects an invalid config with exit 2 naming the file", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ failOn: "urgent" }));
      expect(await main(["scan", "app"])).toBe(2);
      expect(stderr).toContain("whsquad.config.json");
    });

    it("applies the config file when recording a baseline", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ rules: { "AI-*": "off" } }));
      expect(await main(["baseline", "app", "--only", "AI,AUTH"])).toBe(0);
      const doc = JSON.parse(await fs.readFile(path.join(dir, ".whsquad/baseline.json"), "utf8")) as { findings: { ruleId: string }[] };
      expect(doc.findings.some((f) => f.ruleId.startsWith("AI-"))).toBe(false);
    });
  });

  describe("--only / --exclude", () => {
    it("keeps only matching prefixes", async () => {
      const { report } = await scan("app", "--only", "AI,AUTH-003");
      expect(rules(report).length).toBeGreaterThan(0);
      expect(rules(report).every((r) => r.startsWith("AI-") || r === "AUTH-003")).toBe(true);
    });
    it("drops excluded prefixes", async () => {
      const { report } = await scan("app", "--exclude", "AI,AUTH");
      expect(rules(report).some((r) => r.startsWith("AI-") || r.startsWith("AUTH-"))).toBe(false);
    });
  });

  describe("baseline", () => {
    it("records findings, then fails only on new ones", async () => {
      expect(await main(["baseline", "app", "--only", "AI,AUTH"])).toBe(0);
      const file = path.join(dir, ".whsquad/baseline.json");
      const doc = JSON.parse(await fs.readFile(file, "utf8")) as { findings: { id: string; ruleId: string }[]; target: string; toolVersion: string };
      expect(doc.findings.length).toBeGreaterThan(0);
      expect(doc.target).toBe("app");
      expect(doc.toolVersion).toMatch(/^\d+\.\d+\.\d+/);

      const known = await scan("app", "--only", "AI,AUTH", "--baseline", file);
      expect(known.code).toBe(0);
      expect(known.report.findings.every((f) => f.baseline === true)).toBe(true);

      await writeTree(path.join(dir, "app"), {
        "src/app/api/other/[id]/route.ts":
          'export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n' +
          '  await supabase.from("things").delete().eq("id", params.id);\n  return Response.json({ ok: true });\n}\n',
      });
      const fresh = await scan("app", "--only", "AI,AUTH", "--baseline", file);
      expect(fresh.code).toBe(1);
      expect(fresh.report.findings.filter((f) => !f.baseline).length).toBeGreaterThan(0);
      expect(fresh.report.findings.filter((f) => f.baseline).length).toBe(known.report.findings.length);
    });

    it("honours config.baseline and prints the known count in the terminal report", async () => {
      expect(await main(["baseline", "app", "--only", "AUTH"])).toBe(0);
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ baseline: "../.whsquad/baseline.json" }));
      stdout = "";
      expect(await main(["scan", "app", "--only", "AUTH", "--no-color"])).toBe(0);
      expect(stdout).toMatch(/\d+ known \(baseline\)/);
    });

    it("exits 2 for a missing or malformed baseline file", async () => {
      expect(await main(["scan", "app", "--baseline", "nope.json"])).toBe(2);
      await fs.writeFile(path.join(dir, "bad.json"), "{");
      expect(await main(["scan", "app", "--baseline", "bad.json"])).toBe(2);
    });
  });

  describe("coverage", () => {
    it("is in the JSON report and the terminal summary", async () => {
      const { report } = await scan("app");
      expect(report.coverage?.filesIndexed).toBe(4);
      expect(report.coverage?.agentsRun).toBeGreaterThanOrEqual(7);
      expect(report.coverage?.rulesInCatalog).toBeGreaterThan(20);
      stdout = "";
      await main(["scan", "app", "--no-color"]);
      expect(stdout).toMatch(/Checked 4 files with \d+ agents \(\d+ rules\) in \d+\.\d s/);
    });
  });

  describe("verify", () => {
    it("reuses the original scan's options and prints them in the verify command", async () => {
      const first = await scan("app", "--git-history");
      expect(first.report.scanOptions).toEqual({ gitHistory: true, probeDatabase: false, allowPrivate: false });
      expect(first.report.findings.every((f) => f.verify.command.includes("--git-history"))).toBe(true);

      expect(await main(["verify", "AUTH-003", "app"])).toBe(1);
      const saved = JSON.parse(await fs.readFile(path.join(dir, ".whsquad/last-report.json"), "utf8")) as ScanReport;
      expect(saved.scanOptions?.gitHistory).toBe(true);
    });

    it("answers a bad URL with a usage error (exit 2), not an internal error", async () => {
      await scan("app");
      expect(await main(["verify", "AUTH-003", "http://[bad"])).toBe(2);
      expect(stderr).toContain("not a valid URL");
      expect(stderr).not.toContain("Internal error");
    });
  });

  // Security review: a repo's own whsquad.config.json can switch rules off; CI on untrusted PRs ignores it.
  describe("--no-config", () => {
    it("ignores the scanned repo's config so its rules cannot be switched off", async () => {
      await fs.writeFile(path.join(dir, "app/whsquad.config.json"), JSON.stringify({ rules: { "AUTH-*": "off", "WEB-*": "off" } }));
      const hidden = await scan("app");
      expect(rules(hidden.report).some((r) => r.startsWith("AUTH-"))).toBe(false);
      const honest = await scan("app", "--no-config");
      expect(rules(honest.report).some((r) => r.startsWith("AUTH-"))).toBe(true);
      expect(honest.report.config?.source).toBeUndefined();
    });
  });
});
