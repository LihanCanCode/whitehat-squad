import { describe, expect, it } from "vitest";
import { fakeHttp } from "../../helpers/memfs.js";
import { expectNoRawSecrets, fake, googleKey, SAMPLES, scan, stripeKey } from "./fakes.js";

const SK_LIVE = "sk_" + "live_";
const SK_TEST = "sk_" + "test_";
const PK_LIVE = "pk_" + "live_";
const PK_TEST = "pk_" + "test_";
const SB_PUB = "sb_" + "publishable_";

describe("PUBLIC_ prefix needs a variable-name boundary", () => {
  const key = SAMPLES["SEC-004"] as string;

  it("does not treat NOT_PUBLIC_ / IS_PUBLIC_ variables as browser-exposed", async () => {
    const { findings } = await scan({
      ".env.production": `NOT_PUBLIC_API_KEY=${key}\nIS_PUBLIC_KEY=${key}\n`,
      ".gitignore": ".env.production\n",
    });
    expect(findings).toEqual([]);
  });

  it("reports a tracked secret in NOT_PUBLIC_ as an ordinary hardcoded key, not SEC-101", async () => {
    const { findings } = await scan({ "src/cfg.ts": `const NOT_PUBLIC_API_KEY = "${key}";\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-004"]);
  });

  it("still flags real PUBLIC_ / VITE_ / process.env.NEXT_PUBLIC_ variables as SEC-101", async () => {
    const { findings, ctx } = await scan({
      "a.ts": `PUBLIC_API_KEY=${key}\n`,
      "b.ts": `const k = { "VITE_STRIPE": "${key}" };\n`,
      "c.ts": `process.env.NEXT_PUBLIC_STRIPE = "${key}";\n`,
    });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-101", "SEC-101", "SEC-101"]);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });
});

describe("Clerk vs Stripe sk_ keys", () => {
  it("labels a CLERK_ variable as Clerk with the Clerk rotation URL", async () => {
    const { findings, ctx } = await scan({ "src/a.ts": `CLERK_SECRET_KEY="${stripeKey(SK_LIVE, 45)}"\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-029"]);
    expect(findings[0]?.fix.references[0]).toContain("clerk.com");
    expect(ctx.secrets.size).toBe(1);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("labels a STRIPE_ variable as Stripe even when the length looks like Clerk", async () => {
    const { findings } = await scan({ "src/a.ts": `STRIPE_SECRET_KEY="${stripeKey(SK_LIVE, 45)}"\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-004"]);
    expect(findings[0]?.fix.references[0]).toContain("stripe.com");
  });

  it("uses the shape when no variable name helps: 40-60 chars is Clerk, 51-prefixed or old 24-char is Stripe", async () => {
    const ids = async (value: string): Promise<string[]> =>
      (await scan({ "a.ts": `const v = "${value}";\n` })).findings.map((f) => f.ruleId);
    expect(await ids(stripeKey(SK_LIVE, 45))).toEqual(["SEC-029"]);
    expect(await ids(stripeKey(SK_LIVE, 30))).toEqual(["SEC-004"]);
    expect(await ids(stripeKey(SK_LIVE, 99, "51"))).toEqual(["SEC-004"]);
    expect(await ids(stripeKey(SK_LIVE, 45, "51"))).toEqual(["SEC-004"]);
  });

  it("does not report a Stripe test key (not a Clerk key, no live money)", async () => {
    const { findings } = await scan({ "a.ts": `STRIPE_SECRET_KEY="${stripeKey(SK_TEST, 45)}"\n` });
    expect(findings).toEqual([]);
  });

  it("still reports a Clerk test key by its own variable name", async () => {
    const { findings } = await scan({ "a.ts": `CLERK_SECRET_KEY="${stripeKey(SK_TEST, 45)}"\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-029"]);
  });
});

describe("Stripe key length", () => {
  it("detects modern 100+ character live secret and restricted keys", async () => {
    const live = stripeKey(SK_LIVE, 107, "51");
    const restricted = stripeKey("rk_" + "live_", 107, "51");
    const { findings, ctx } = await scan({ "a.ts": `const a = "${live}";\nconst b = "${restricted}";\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-004", "SEC-004"]);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("detects keys right up to the 247 character cap and stays bounded beyond it", async () => {
    const atCap = await scan({ "a.ts": `const a = "${stripeKey(SK_LIVE, 247, "51")}";\n` });
    expect(atCap.findings.map((f) => f.ruleId)).toEqual(["SEC-004"]);
    const beyond = await scan({ "a.ts": `const a = "${stripeKey(SK_LIVE, 600, "51")}";\n` });
    expect(beyond.findings.filter((f) => f.ruleId === "SEC-004")).toEqual([]);
  });

  it("does not match a too-short body", async () => {
    const { findings } = await scan({ "a.ts": `const a = "${stripeKey(SK_LIVE, 20)}";\n` });
    expect(findings).toEqual([]);
  });
});

describe("SEC-090 excludes public key shapes", () => {
  it("ignores the Firebase web apiKey, Stripe/Clerk publishable keys and Supabase publishable keys", async () => {
    const { findings } = await scan({
      "src/firebase.ts": `export const cfg = { apiKey: "${googleKey()}", authDomain: "x.firebaseapp.com" };\n`,
      "src/stripe.ts": `const publishableKey = "${PK_LIVE}${fake(40)}";\nconst testKey = "${PK_TEST}${fake(40)}";\n`,
      "src/supa.ts": `const anonKey = "${SB_PUB}${fake(30)}";\nconst k2 = "${SB_PUB}${fake(24)}";\n`,
    });
    expect(findings).toEqual([]);
  });

  it("still fires on an unrelated high-entropy secret assignment", async () => {
    const { findings } = await scan({ "src/a.ts": `const sessionSecret = "${fake(32)}9";\nconst pk = "${PK_LIVE}${fake(40)}";\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-090"]);
  });
});

describe(".npmrc and .yarnrc.yml belong to supply-chain", () => {
  const token = SAMPLES["SEC-034"] as string;

  it("does not report npm tokens in .npmrc / .yarnrc.yml (SUP-008 owns them)", async () => {
    const { findings } = await scan({
      ".npmrc": `//registry.npmjs.org/:_authToken=${token}\n`,
      "packages/a/.npmrc": `//registry.npmjs.org/:_authToken=${token}\n`,
      ".yarnrc.yml": `npmAuthToken: ${token}\n`,
    });
    expect(findings).toEqual([]);
  });

  it("still reports the same token anywhere else", async () => {
    const { findings } = await scan({ "src/a.ts": `const t = "${token}";\n`, "ci/publish.sh": `NPM_TOKEN=${token}\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-034", "SEC-034"]);
  });
});

describe("test-ish path words do not downgrade live URLs", () => {
  const target = new URL("https://app.test/");
  const stripe = SAMPLES["SEC-004"] as string;

  it("keeps high confidence for a script served from /docs/ or /examples/", async () => {
    const http = fakeHttp({
      "https://app.test/": { body: `<script src="/docs/app.js"></script><script src="/examples/b.js"></script>` },
      "https://app.test/docs/app.js": { body: `var a="${stripe}";` },
      "https://app.test/examples/b.js": { body: `var a="${SAMPLES["SEC-005"]}";` },
    });
    const { findings } = await scan({}, { mode: "live", target, http });
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.confidence === "high")).toBe(true);
  });

  it("still downgrades the same file in a static scan", async () => {
    const { findings } = await scan({ "docs/app.js": `var a="${stripe}";\n` });
    expect(findings[0]?.confidence).toBe("low");
  });
});
