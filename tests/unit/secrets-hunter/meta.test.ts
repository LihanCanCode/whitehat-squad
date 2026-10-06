import { describe, expect, it } from "vitest";
import { RULES } from "../../../src/agents/secrets-hunter/rules.meta.js";
import { SECRET_PATTERNS } from "../../../src/data/secret-patterns.js";
import { SAMPLES, scan } from "./fakes.js";

const byId = new Map(RULES.map((r) => [r.id, r]));

describe("secrets-hunter rule metadata", () => {
  it("has unique ids and fully populated entries", () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
    for (const r of RULES) {
      expect(r.agent).toBe("secrets-hunter");
      expect(r.title.length).toBeGreaterThan(5);
      expect(r.summary.length).toBeGreaterThan(30);
      expect(r.fix.length).toBeGreaterThan(20);
      expect(r.cwe).toMatch(/^CWE-\d+$/);
      expect(r.owasp).toMatch(/^A\d\d$/);
      expect(r.modes.length).toBeGreaterThan(0);
    }
  });

  it("has an entry for every pattern id with the pattern's own severity", () => {
    for (const p of SECRET_PATTERNS) {
      const meta = byId.get(p.id);
      expect(meta, p.id).toBeDefined();
      expect(meta?.severity).toBe(p.severity);
      expect(meta?.title).toContain(p.name);
      expect(meta?.cwe).toBe("CWE-798");
    }
  });

  it("covers every non-pattern rule the agent raises", () => {
    for (const id of ["SEC-090", "SEC-100", "SEC-101", "SEC-102", "SEC-L01", "SEC-110", "SEC-111", "SEC-112"]) {
      expect(byId.has(id), id).toBe(true);
    }
    expect(byId.get("SEC-101")?.severity).toBe("critical");
    expect(byId.get("SEC-110")?.severity).toBe("high");
    expect(byId.get("SEC-L01")?.modes).toEqual(["live"]);
  });

  it("covers every rule id an actual scan emits", async () => {
    const files: Record<string, string> = {
      ".env": "FOO=bar123456789\n",
      "Dockerfile": "FROM a\nCOPY . .\nENV INTERNAL_API_KEY=aB3dE5fG7hJ9kL2mN4pQ6\n",
      "src/a.ts": `const JWT_SECRET = "secret";\nconst sessionKey = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU1vW0yZ9";\nNEXT_PUBLIC_X=${SAMPLES["SEC-010"]}\n`,
    };
    for (const [id, sample] of Object.entries(SAMPLES)) files[`s/${id}.ts`] = sample;
    const { findings } = await scan(files);
    expect(findings.length).toBeGreaterThan(50);
    for (const f of findings) expect(byId.has(f.ruleId), f.ruleId).toBe(true);
  });
});
