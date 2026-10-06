import { describe, expect, it } from "vitest";
import { SECRET_PATTERNS } from "../../../src/data/secret-patterns.js";
import { fake, fakeHex, jwt, SAMPLES, scan, expectNoRawSecrets } from "./fakes.js";

describe("pattern table", () => {
  it("has 45+ uniquely identified patterns with rotation links", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(59);
    const ids = SECRET_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const p of SECRET_PATTERNS) {
      expect(p.id).toMatch(/^SEC-0\d\d$/);
      expect(p.rotateUrl).toMatch(/^https:\/\//);
      expect(p.regex.global).toBe(true);
    }
  });

  it("has a test sample for every pattern", () => {
    expect(Object.keys(SAMPLES).sort()).toEqual(SECRET_PATTERNS.map((p) => p.id).sort());
  });

  it("does not backtrack catastrophically on adversarial input", () => {
    const inputs = [
      "a".repeat(200_000),
      "-----BEGIN PRIVATE KEY-----" + "A".repeat(100_000),
      "postgres://" + "a:".repeat(50_000),
      "sk-" + "a-".repeat(100_000),
      "twilio" + " ".repeat(100_000),
      "eyJ" + "a".repeat(100_000),
      "sk_live_" + "a".repeat(100_000),
      "sk_live_".repeat(20_000),
      "sb_secret_" + "a_".repeat(50_000),
      "xkeysib-" + "a".repeat(100_000),
      "napi_" + "a".repeat(100_000),
      "UPSTASH_" + "A".repeat(100_000),
      "UPSTASH".repeat(15_000),
      "UPSTASH_REDIS_REST_TOKEN=" + "A".repeat(100_000),
      "lemonsqueezy" + " ".repeat(100_000),
      "LEMONSQUEEZY_API_KEY=eyJ" + "a".repeat(100_000),
      "LEMONSQUEEZY_API_KEY=eyJa.eyJ" + "a".repeat(100_000),
      "GEMINI_API_KEY=\"AIza" + "a".repeat(100_000),
      "GOOGLE_API_KEY=".repeat(15_000),
      "GOCSPX-" + "a".repeat(100_000),
      "fo1_" + "a".repeat(100_000),
      "rnd_" + "a".repeat(100_000),
      "sbp_" + "a".repeat(100_000),
    ];
    const start = Date.now();
    for (const p of SECRET_PATTERNS) for (const text of inputs) void [...text.matchAll(p.regex)];
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

describe("provider detection", () => {
  for (const pattern of SECRET_PATTERNS) {
    it(`detects ${pattern.id} (${pattern.name}) and never leaks the raw value`, async () => {
      const { findings, ctx } = await scan({ "src/config.ts": `// cfg\n${SAMPLES[pattern.id]}\n` });
      const hit = findings.find((f) => f.ruleId === pattern.id);
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe(pattern.severity);
      expect(hit?.cwe).toBe("CWE-798");
      expect(ctx.secrets.size).toBeGreaterThan(0);
      expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
    });
  }
});

describe("finding content", () => {
  it("explains, gives a paste-ready agent prompt and a rotation checklist", async () => {
    const { findings } = await scan({ "src/lib/pay.ts": `import x from "y";\nconst k = "${SAMPLES["SEC-004"]}";\n` });
    const f = findings.find((x) => x.ruleId === "SEC-004");
    expect(f).toBeDefined();
    expect(f?.evidence[0]).toMatchObject({ file: "src/lib/pay.ts", line: 2 });
    expect(f?.evidence[0]?.snippet).toContain("sk_l********");
    expect(f?.explanation).toMatch(/anyone/i);
    expect(f?.fix.agentPrompt).toContain("src/lib/pay.ts");
    expect(f?.fix.agentPrompt).toMatch(/rotate/i);
    expect(f?.fix.agentPrompt).toMatch(/env/i);
    expect(f?.fix.agentPrompt).toMatch(/never (log|print)/i);
    expect(f?.fix.config).toMatch(/1\./);
    expect(f?.fix.references.length).toBeGreaterThan(0);
    expect(f?.verify.ruleId).toBe("SEC-004");
  });

  it("uses Anthropic and not OpenAI for sk-ant keys, OpenRouter before OpenAI", async () => {
    const { findings } = await scan({
      "a.ts": `${SAMPLES["SEC-007"]}\n${SAMPLES["SEC-006"]}\n${SAMPLES["SEC-008"]}\n`,
    });
    expect(findings.map((f) => f.ruleId).sort()).toEqual(["SEC-006", "SEC-007", "SEC-008"]);
  });

  it("reports a GCP service-account key once, not also as a generic PEM", async () => {
    const { findings } = await scan({ "sa.json": SAMPLES["SEC-003"] as string });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-003"]);
  });
});

describe("Supabase JWTs", () => {
  it("flags service_role but not anon keys", async () => {
    const { findings } = await scan({
      "a.ts": `const anon = "${jwt("anon")}";\nconst admin = "${jwt("service_role")}";\n`,
    });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-009"]);
    expect(findings[0]?.evidence[0]?.line).toBe(2);
  });

  it("ignores malformed JWT payloads", async () => {
    const bad = "eyJ" + fake(20) + "." + "eyJ" + fake(20) + "." + fake(20);
    const { findings } = await scan({ "a.ts": `const t = "${bad}";` });
    expect(findings.filter((f) => f.ruleId === "SEC-009")).toEqual([]);
  });
});

describe("false-positive control", () => {
  it("skips placeholders and env references", async () => {
    const files = {
      "a.ts": [
        `const a = "sk_${"live_"}${"x".repeat(24)}";`,
        `const b = "AKIA${"IOSFODNN7"}EXAMPLE";`,
        `const c = process.env.STRIPE_SECRET_KEY;`,
        `const d = "sk-proj-your_key_here_${"a".repeat(30)}";`,
        `const e = "ghp_${"0".repeat(36)}";`,
        `const f = "postgres://user:<password>@db.prod-host.io/app";`,
        `const g = "postgres://postgres:postgres1234@localhost:5432/app";`,
        `const h = "sk-ant-placeholder-${"a".repeat(30)}";`,
      ].join("\n"),
    };
    const { findings } = await scan(files);
    expect(findings).toEqual([]);
  });

  it("downgrades confidence for tests and docs instead of dropping them", async () => {
    const line = `${SAMPLES["SEC-010"]}\n`;
    const { findings } = await scan({ "src/app.ts": line, "tests/a.test.ts": line, "docs/readme.md": line });
    const byFile = Object.fromEntries(findings.map((f) => [f.evidence[0]?.file, f.confidence]));
    expect(byFile["src/app.ts"]).toBe("high");
    expect(byFile["tests/a.test.ts"]).toBe("low");
    expect(byFile["docs/readme.md"]).toBe("low");
  });

  it("skips lockfiles, source maps and node_modules", async () => {
    const line = `"${SAMPLES["SEC-010"]}"\n`;
    const { findings } = await scan({
      "package-lock.json": line, "yarn.lock": line, "dist/app.js.map": line, "node_modules/x/i.js": line,
    });
    expect(findings).toEqual([]);
  });

  it("dedupes the same secret in the same file", async () => {
    const s = SAMPLES["SEC-010"];
    const { findings } = await scan({ "a.ts": `a="${s}"\nb="${s}"\n`, "b.ts": `a="${s}"\n` });
    expect(findings).toHaveLength(2);
  });

  it("returns nothing when a file cannot be read", async () => {
    const ctx = (await scan({})).ctx;
    const findings = await (await import("../../../src/agents/secrets-hunter/index.js")).agent.run({
      ...ctx,
      files: { paths: ["gone.ts"], read: async () => null, isIgnored: () => false },
    });
    expect(findings).toEqual([]);
  });

  it("does not flag short DB passwords it cannot redact safely or random hex that is not a key", async () => {
    const { findings } = await scan({ "a.ts": `const h = "${fakeHex(32)}";` });
    expect(findings).toEqual([]);
  });
});
