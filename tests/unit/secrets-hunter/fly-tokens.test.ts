import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/secrets-hunter/index.js";
import { memContext } from "../../helpers/memfs.js";

// Built at runtime: never commit a literal that looks like a real token.
// Varied characters: a run of 8+ identical characters is (correctly) treated as a placeholder.
const body = Array.from({ length: 120 }, (_, i) => "Kq7Zp2Wm9Xv4Lr8Tb3Nd6Hf1Jc5Gs0Y"[(i * 7) % 32]).join("");
const macaroon = ["fm2", "_", body].join("");

describe("Fly.io macaroon tokens (published flyio-access-token shapes)", () => {
  it("detects an fm2_ token and never leaks it into the report", async () => {
    const ctx = memContext({ "deploy.sh": `export FLY_API_TOKEN="${macaroon}"\n` });
    const findings = await agent.run(ctx);
    expect(findings.map((f) => f.ruleId)).toContain("SEC-056");
    expect(JSON.stringify(findings)).not.toContain(macaroon);
    expect(ctx.secrets.has(macaroon)).toBe(true);
  });

  it("does not fire on a short fm2_-prefixed identifier", async () => {
    const findings = await agent.run(memContext({ "a.ts": 'const id = "fm2_settings";\n' }));
    expect(findings.map((f) => f.ruleId)).not.toContain("SEC-056");
  });
});
