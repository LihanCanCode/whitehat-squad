import { describe, expect, it } from "vitest";
import { expectNoRawSecrets, fake, fakeHex, googleKey, lemonJwt, jwt, SAMPLES, scan } from "./fakes.js";

const SB_SECRET = "sb_" + "secret_";
const SB_PUB = "sb_" + "publishable_";

async function ids(files: Record<string, string>): Promise<string[]> {
  return (await scan(files)).findings.map((f) => f.ruleId);
}

describe("Supabase new-style API keys", () => {
  it("SEC-050 flags a secret key as critical without leaking it", async () => {
    const { findings, ctx } = await scan({ "src/a.ts": `const k = "${SAMPLES["SEC-050"]}";\n` });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-050", severity: "critical", cwe: "CWE-798" });
    expect(findings[0]?.fix.references[0]).toContain("supabase.com");
    expect(ctx.secrets.size).toBe(1);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("SEC-050 ignores placeholders and truncated keys but fires in a public var as SEC-101", async () => {
    expect(await ids({ "a.ts": `k="${SB_SECRET}${"x".repeat(24)}"\nj="${SB_SECRET}your_key_here_please_000"\nm="${SB_SECRET}abc"\n` })).toEqual([]);
    expect(await ids({ "a.ts": `NEXT_PUBLIC_SUPABASE_SECRET=${SAMPLES["SEC-050"]}\n` })).toEqual(["SEC-101"]);
  });

  it("never reports a publishable key, in a public var or not", async () => {
    const pub = SB_PUB + fake(24) + "_" + fake(8);
    expect(await ids({
      "src/a.ts": `const k = "${pub}";\n`,
      ".env.local": `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${pub}\nSUPABASE_PUBLISHABLE_KEY=${pub}\n`,
      ".gitignore": ".env.local\n",
    })).toEqual([]);
  });

  it("SEC-051 flags a personal access token and skips a repeated-character placeholder", async () => {
    expect(await ids({ "a.ts": `t="${SAMPLES["SEC-051"]}"` })).toEqual(["SEC-051"]);
    expect(await ids({ "a.ts": `t="sb${"p_"}${"0".repeat(40)}"` })).toEqual([]);
    expect(await ids({ "a.ts": `t="sb${"p_"}${fakeHex(30)}"` })).toEqual([]);
  });
});

describe("Google OAuth client secret (SEC-052)", () => {
  it("flags the secret as high and skips placeholders", async () => {
    const { findings, ctx } = await scan({ "a.ts": `GOOGLE_CLIENT_SECRET="${SAMPLES["SEC-052"]}"\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-052"]);
    expect(findings[0]?.severity).toBe("high");
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
    expect(await ids({ "a.ts": `s="GOC${"SPX-"}${"x".repeat(28)}"\nt="GOC${"SPX-"}your_secret_goes_here_000000"\n` })).toEqual([]);
  });
});

describe("Upstash Redis REST token (SEC-053)", () => {
  it("flags a literal token assigned to UPSTASH_*_TOKEN, in env and code", async () => {
    const token = fake(44) + "==";
    const { findings, ctx } = await scan({
      ".env.production": `UPSTASH_REDIS_REST_TOKEN=${token}\n`,
      ".gitignore": "",
      "src/redis.ts": `new Redis({ UPSTASH_REDIS_REST_READ_TOKEN: "${token}" })\n`,
    });
    expect(findings.map((f) => f.ruleId)).toContain("SEC-053");
    expect(findings.filter((f) => f.ruleId === "SEC-053").every((f) => f.severity === "high")).toBe(true);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("ignores env references, placeholders, the URL variable and unrelated variables", async () => {
    expect(await ids({
      "a.ts": [
        "const url = process.env.UPSTASH_REDIS_REST_URL;",
        "const t = process.env.UPSTASH_REDIS_REST_TOKEN;",
        `UPSTASH_REDIS_REST_URL="https://eu1-lucky-cat-1234.upstash.io"`,
        `UPSTASH_REDIS_REST_TOKEN="your_token_goes_here_0000000000000000"`,
        `UPSTASH_REDIS_REST_TOKEN="${"A".repeat(44)}=="`,
        `const blob = "${fake(44)}==";`,
      ].join("\n"),
    })).toEqual([]);
  });
});

describe("Neon, Render, Fly.io and Brevo keys", () => {
  const cases: readonly (readonly [string, string, string])[] = [
    ["SEC-054", "napi_", "Neon"],
    ["SEC-055", "rnd_", "Render"],
    ["SEC-056", "fo1_", "Fly.io"],
    ["SEC-057", "xkeysib-", "Brevo"],
  ];
  for (const [id, prefix, vendor] of cases) {
    it(`${id} (${vendor}) fires, is high, and never leaks`, async () => {
      const { findings, ctx } = await scan({ "src/a.ts": `const k = "${SAMPLES[id]}";\n` });
      expect(findings.map((f) => f.ruleId)).toEqual([id]);
      expect(findings[0]?.severity).toBe("high");
      expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
      expect(SAMPLES[id]?.startsWith(prefix)).toBe(true);
    });

    it(`${id} (${vendor}) skips placeholder and wrong-length values`, async () => {
      const sample = SAMPLES[id] as string;
      const placeholder = prefix + "x".repeat(sample.length - prefix.length);
      const tooShort = sample.slice(0, prefix.length + 8);
      expect(await ids({ "a.ts": `a="${placeholder}"\nb="${tooShort}"\nc="${prefix}example_key"\n` })).toEqual([]);
    });
  }

  it("SEC-055 skips snake_case identifiers that merely start with rnd_", async () => {
    expect(await ids({ "a.ts": `const f = rnd_${"abcdefghijklmnopqrstuvwxyzabcdef"};\n` })).toEqual([]);
  });
});

describe("Lemon Squeezy API key (SEC-058)", () => {
  it("flags the JWT-shaped key only when assigned to a LEMONSQUEEZY_ key variable", async () => {
    const { findings, ctx } = await scan({ "src/ls.ts": `${SAMPLES["SEC-058"]}\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-058"]);
    expect(findings[0]?.severity).toBe("high");
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("does not flag the same JWT shape under another name, an env reference or a Supabase anon JWT", async () => {
    expect(await ids({
      "a.ts": [
        `const bearer = "${lemonJwt()}";`,
        "LEMONSQUEEZY_API_KEY=process.env.LEMONSQUEEZY_API_KEY",
        `LEMONSQUEEZY_API_KEY="${jwt("anon")}"`,
        `LEMONSQUEEZY_API_KEY="your_lemon_squeezy_key"`,
      ].join("\n"),
    })).toEqual([]);
  });
});

describe("Gemini / Google AI key (SEC-059)", () => {
  for (const name of ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY", "GOOGLE_AI_API_KEY"]) {
    it(`flags an AIza key assigned to ${name}`, async () => {
      const key = googleKey();
      const { findings, ctx } = await scan({ [".env.production"]: `${name}=${key}\n`, "src/a.ts": `const ${name} = "${key}";\n` });
      expect(findings.filter((f) => f.ruleId === "SEC-059").length).toBeGreaterThan(0);
      expect(findings.find((f) => f.ruleId === "SEC-059")?.severity).toBe("high");
      expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
    });
  }

  it("keeps the Firebase web config and maps keys excluded", async () => {
    expect(await ids({
      "src/firebase.ts": `const cfg = { apiKey: "${googleKey()}" };\nconst GOOGLE_MAPS_API_KEY = "${googleKey()}";\nconst x = "${googleKey()}";\n`,
    })).toEqual([]);
  });

  it("does not flag a placeholder or an env reference", async () => {
    expect(await ids({ "a.ts": `GEMINI_API_KEY="AIza${"x".repeat(35)}"\nconst k = process.env.GEMINI_API_KEY;\nGEMINI_API_KEY=\n` })).toEqual([]);
  });

  it("reports it as SEC-101 when the variable ships to the browser", async () => {
    expect(await ids({ "a.ts": `NEXT_PUBLIC_GEMINI_API_KEY="${googleKey()}"\n` })).toEqual(["SEC-101"]);
  });
});
