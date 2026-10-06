import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/secrets-hunter/index.js";
import { fakeHttp } from "../../helpers/memfs.js";
import { fake, fakeHex, jwt, SAMPLES, scan, expectNoRawSecrets } from "./fakes.js";

describe("SEC-090 generic high-entropy assignment", () => {
  it("flags a quoted high-entropy secret assignment at low confidence", async () => {
    const value = fake(32) + "9";
    const { findings, ctx } = await scan({ "src/auth.ts": `const sessionSecret = "${value}";\n` });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-090", confidence: "low" });
    expect(ctx.secrets.has(value)).toBe(true);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("flags unquoted values in env files", async () => {
    const { findings } = await scan({ ".env.example": `API_TOKEN=${fake(32)}9\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-090"]);
  });

  it("ignores low-entropy, short, identifier-like and reference values", async () => {
    const { findings } = await scan({
      "a.ts": [
        `const password = "aaaaaaaaaaaaaaaaaaaaaaaa1";`,
        `const token = "short1";`,
        `const apiKey = "getUserApiKeyFromRequestHeaders";`,
        `const secret = "https://example.com/some/long/path/with1/segments";`,
        `const key = process.env.SOME_VERY_LONG_ENVIRONMENT_KEY_1;`,
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });
});

describe("SEC-100 committed .env", () => {
  it("flags a tracked .env as high without echoing its values", async () => {
    const { findings, ctx } = await scan({ ".env": "FOO=bar\nBAZ=qux\n", ".gitignore": "node_modules\n" });
    const f = findings.find((x) => x.ruleId === "SEC-100");
    expect(f).toMatchObject({ severity: "high", agentId: "secrets-hunter" });
    expect(f?.evidence[0]?.file).toBe(".env");
    expect(f?.fix.agentPrompt).toMatch(/\.gitignore/);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("flags .env.local and .env.production too", async () => {
    const { findings } = await scan({
      ".env.local": "SOME_TOKEN=abcdefgh12345678\n",
      "apps/web/.env.production": "SOME_TOKEN=abcdefgh12345678\n",
    });
    expect(findings.filter((f) => f.ruleId === "SEC-100")).toHaveLength(2);
  });

  it("is fine with .env.example and with gitignored .env", async () => {
    const real = "STRIPE=" + SAMPLES["SEC-004"] + "\n";
    const { findings } = await scan({
      ".env.example": "FOO=\nBAR=your_key_here\n",
      ".env": real,
      ".gitignore": ".env\n.env.*\n!.env.example\n",
    });
    expect(findings).toEqual([]);
  });
});

describe("SEC-101 secrets in public env vars", () => {
  it("is critical for a real secret in NEXT_PUBLIC_/VITE_/REACT_APP_ vars", async () => {
    const { findings, ctx } = await scan({
      ".env.production": `NEXT_PUBLIC_STRIPE_KEY=${SAMPLES["SEC-004"]}\nVITE_OPENAI=${SAMPLES["SEC-008"]}\n`,
      ".gitignore": ".env.production\n",
      "src/cfg.ts": `export const c = { REACT_APP_GH: "${SAMPLES["SEC-010"]}" };\n`,
    });
    const hits = findings.filter((f) => f.ruleId === "SEC-101");
    expect(hits).toHaveLength(3);
    expect(hits.every((f) => f.severity === "critical")).toBe(true);
    expect(findings.some((f) => f.ruleId === "SEC-004")).toBe(false);
    expect(hits[0]?.explanation).toMatch(/bundle|browser|visitor/i);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("does not flag the Supabase anon key in a public var", async () => {
    const { findings } = await scan({
      ".env.local": `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt("anon")}\n`,
      ".gitignore": ".env.local\n",
    });
    expect(findings).toEqual([]);
  });
});

describe("SEC-L01 live mode", () => {
  const target = new URL("https://app.test/");

  it("finds secret-class keys in HTML and scripts, with url evidence", async () => {
    const http = fakeHttp({
      "https://app.test/": {
        body: `<html><script src="/app.js"></script><script>var k="${SAMPLES["SEC-005"]}"</script></html>`,
      },
      "https://app.test/app.js": { body: `var a="${SAMPLES["SEC-004"]}";var b="${jwt("anon")}";var f="AIza${fake(35)}";` },
    });
    const { findings, ctx } = await scan({}, { mode: "live", target, http });
    expect(findings.every((f) => f.ruleId === "SEC-L01")).toBe(true);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.evidence[0]?.url).sort()).toEqual(["https://app.test/", "https://app.test/app.js"]);
    expect(findings.every((f) => f.evidence[0]?.file === undefined)).toBe(true);
    expect(ctx.secrets.size).toBe(2);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("does not flag anon keys or Firebase apiKey in a bundle", async () => {
    const http = fakeHttp({
      "https://app.test/": { body: `<script src="/m.js"></script>` },
      "https://app.test/m.js": {
        body: `{apiKey:"AIza${fake(35)}",anon:"${jwt("anon")}"} const t = "${fakeHex(32)}"`,
      },
    });
    const { findings } = await scan({}, { mode: "live", target, http });
    expect(findings).toEqual([]);
  });

  it("returns nothing when the site is unreachable", async () => {
    const { findings } = await scan({}, { mode: "live", target, http: fakeHttp({}) });
    expect(findings).toEqual([]);
  });

  it("declares both modes", () => {
    expect(agent.id).toBe("secrets-hunter");
    expect(agent.modes).toEqual(["static", "live"]);
  });
});
