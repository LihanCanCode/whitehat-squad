// Fake credentials are assembled at runtime so no real-looking secret literal is ever committed.
import { agent } from "../../../src/agents/secrets-hunter/index.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext, type TestContext } from "../../helpers/memfs.js";

const ALPHA = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU1vW0yZ";
const HEX = "a1b2c3d4e5f60789";

/** Deterministic, high-entropy, alphanumeric (never contains "x" runs, "example", etc.). */
export function fake(n: number): string {
  return Array.from({ length: n }, (_, i) => ALPHA[(i * 7 + 3) % ALPHA.length]).join("");
}
export function fakeUp(n: number): string {
  return fake(n).toUpperCase();
}
export function fakeHex(n: number): string {
  return Array.from({ length: n }, (_, i) => HEX[(i * 5 + 1) % HEX.length]).join("");
}
function b64url(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
export function jwt(role: string): string {
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ iss: "supabase", role })}.${fake(43)}`;
}

/** Lemon Squeezy keys are long RS256-style JWTs; the shape is built, never written out. */
export function lemonJwt(): string {
  return "ey" + "J" + fake(120) + "." + "ey" + "J" + fake(300) + "." + fake(150);
}
/** Google API key shape (prefix + 35 chars), assembled at runtime. */
export function googleKey(): string {
  return "AI" + "za" + fake(35);
}
/** Stripe-style key with the given prefix ("sk_live_", "rk_live_") and body length. */
export function stripeKey(prefix: string, bodyLength: number, bodyPrefix = ""): string {
  return prefix + bodyPrefix + fake(bodyLength - bodyPrefix.length);
}

/** One sample per pattern id. */
export const SAMPLES: Record<string, string> = {
  "SEC-001": "AK" + "IA" + fakeUp(16),
  "SEC-002": `aws_secret_access_key = "${fake(40)}"`,
  "SEC-003": `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\n${fake(60)}\\n-----END PRIVATE KEY-----\\n"}`,
  "SEC-004": "sk_" + "live_" + fake(30),
  "SEC-005": "whsec_" + fake(32),
  "SEC-006": "sk-or-" + "v1-" + fakeHex(64),
  "SEC-007": "sk-ant-" + "api03-" + fake(40),
  "SEC-008": "sk-proj-" + fake(48),
  "SEC-009": jwt("service_role"),
  "SEC-010": "ghp_" + fake(36),
  "SEC-011": "github_pat_" + fake(40),
  "SEC-012": "xoxb-" + "123456789012-" + fake(24),
  "SEC-013": "https://hooks.slack.com/services/T" + fakeUp(9) + "/B" + fakeUp(9) + "/" + fake(24),
  "SEC-014": "SK" + fakeHex(32),
  "SEC-015": `twilio_auth_token = "${fakeHex(32)}"`,
  "SEC-016": "SG." + fake(22) + "." + fake(43),
  "SEC-017": "key-" + fakeHex(32),
  "SEC-018": "re_" + fake(8) + "_" + fake(26),
  "SEC-019": `postmark_server_token = "${fakeHex(8)}-${fakeHex(4)}-${fakeHex(4)}-${fakeHex(4)}-${fakeHex(12)}"`,
  "SEC-020": "M" + fake(23) + "." + fake(6) + "." + fake(27),
  "SEC-021": "https://discord.com/api/webhooks/123456789012345678/" + fake(64),
  "SEC-022": "123456789:AA" + fake(33),
  "SEC-023": "hf_" + fake(34),
  "SEC-024": "r8_" + fake(37),
  "SEC-025": "gsk_" + fake(52),
  "SEC-026": `mistral_api_key = "${fake(32)}"`,
  "SEC-027": `cohere_api_key = "${fake(40)}"`,
  "SEC-028": "pcsk_" + fake(6) + "_" + fake(50),
  "SEC-029": "sk_" + "test_" + fake(45),
  "SEC-030": "-----BEGIN RSA PRIVATE KEY-----\n" + fake(64) + "\n-----END RSA PRIVATE KEY-----",
  "SEC-031": "postgres://app:" + fake(16) + "@db.prod-host.io:5432/app",
  "SEC-032": "mongodb+srv://u:" + fake(16) + "@cluster0.abcde.mongodb.net/db",
  "SEC-033": "redis://default:" + fake(20) + "@cache.prod-host.io:6379",
  "SEC-034": "npm_" + fake(36),
  "SEC-035": `vercel_token = "${fake(24)}"`,
  "SEC-036": "nfp_" + fake(40),
  "SEC-037": `algolia_admin_api_key = "${fakeHex(32)}"`,
  "SEC-038": "sk." + "eyJ" + fake(40) + "." + fake(30),
  "SEC-039": "shpat_" + fakeHex(32),
  "SEC-040": "sq0csp-" + fake(43),
  "SEC-041": "dop_v1_" + fakeHex(64),
  "SEC-042": "lin_api_" + fake(40),
  "SEC-043": "sntrys_" + fake(60),
  "SEC-044": "dp.pt." + fake(44),
  "SEC-045": "pscale_tkn_" + fake(40),
  "SEC-046": "dapi" + fakeHex(32),
  "SEC-047": "pplx-" + fake(48),
  "SEC-048": "xai-" + fake(80),
  "SEC-049": "mysql://root:" + fake(16) + "@db.prod-host.io:3306/app",
  "SEC-050": "sb_" + "secret_" + fake(22) + "_" + fake(8),
  "SEC-051": "sb" + "p_" + fakeHex(40),
  "SEC-052": "GOC" + "SPX-" + fake(28),
  "SEC-053": `UPSTASH_REDIS_REST_TOKEN="${fake(44)}=="`,
  "SEC-054": "na" + "pi_" + fake(60).toLowerCase(),
  "SEC-055": "rn" + "d_" + fake(32),
  "SEC-056": "fo" + "1_" + fake(43),
  "SEC-057": "xkey" + "sib-" + fakeHex(64) + "-" + fake(16),
  "SEC-058": `LEMONSQUEEZY_API_KEY="${lemonJwt()}"`,
  "SEC-059": `GEMINI_API_KEY="${googleKey()}"`,
};

export async function scan(
  files: Record<string, string>,
  overrides: Parameters<typeof memContext>[1] = {},
): Promise<{ findings: Finding[]; ctx: TestContext }> {
  const ctx = memContext(files, overrides);
  const findings = await agent.run(ctx);
  return { findings, ctx };
}

export function expectNoRawSecrets(findings: readonly Finding[], ctx: TestContext): string[] {
  const json = JSON.stringify(findings);
  return [...ctx.secrets].filter((s) => json.includes(s));
}
