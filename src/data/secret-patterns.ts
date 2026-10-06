import type { Severity } from "../core/types.js";

export interface SecretPattern {
  readonly id: string;
  readonly name: string;
  /** Global regex with bounded quantifiers. Capture group 1 (if present) is the secret; otherwise the whole match. */
  readonly regex: RegExp;
  readonly severity: Severity;
  readonly rotateUrl: string;
  /** What an attacker can do with it, finishing the sentence "...and ". */
  readonly impact?: string;
  /** Extra check after the regex matched. Return false to drop the match. */
  readonly validate?: (value: string, match: RegExpMatchArray) => boolean;
}

/** Supabase issues JWTs for both the public anon role and the all-powerful service_role. Only the latter is a leak. */
function isServiceRoleJwt(value: string): boolean {
  const payload = value.split(".")[1];
  if (!payload) return false;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { role?: unknown; iss?: unknown };
    // "supabase-demo" is the well-known key from the Supabase docs / local CLI, not a real project key.
    return decoded.role === "service_role" && decoded.iss !== "supabase-demo";
  } catch {
    return false;
  }
}

const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)$/i;

/** DB URLs only matter when they point at a real (dotted, non-local) host. */
function isRemoteDbUrl(_value: string, match: RegExpMatchArray): boolean {
  const afterAt = match[0].slice(match[0].lastIndexOf("@") + 1);
  const host = afterAt.split(/[/:?]/)[0] ?? "";
  return host.includes(".") && !LOCAL_HOST.test(host);
}

const hasDigit = (value: string): boolean => /\d/.test(value);

/**
 * Values that look like secrets to an entropy heuristic but are public by design (or harmless test
 * mode): Stripe/Clerk publishable keys, Stripe test-mode secrets, Supabase publishable keys and
 * Google `AIza` browser keys (the Firebase web config). The generic SEC-090 detector skips them; a
 * server-side Gemini key is still caught by name in SEC-059.
 */
export const PUBLIC_KEY_SHAPE = /^(?:pk_(?:live|test)_|sk_test_|rk_test_|sb_publishable_|AIza)/;

const CLERK_CONTEXT = /clerk/i;
const STRIPE_CONTEXT = /stripe/i;
const CONTEXT_CHARS = 80;

/** Text on the same line before the match, e.g. `CLERK_SECRET_KEY="`. */
function lineBefore(match: RegExpMatchArray): string {
  const input = match.input ?? "";
  const index = match.index ?? 0;
  const lineStart = input.lastIndexOf("\n", index - 1) + 1;
  return input.slice(Math.max(lineStart, index - CONTEXT_CHARS), index);
}

/**
 * Stripe and Clerk both issue `sk_live_` / `sk_test_` keys. The variable name on the line decides
 * first; otherwise the shape does (Clerk bodies are 40-60 chars and never start with Stripe's
 * account-id marker "51"); anything unclear is treated as Stripe.
 */
function classifySecretKey(body: string, match: RegExpMatchArray): "stripe" | "clerk" {
  const clerkLength = body.length >= 40 && body.length <= 60;
  const before = lineBefore(match);
  if (CLERK_CONTEXT.test(before)) return clerkLength ? "clerk" : "stripe";
  if (STRIPE_CONTEXT.test(before)) return "stripe";
  return clerkLength && !body.startsWith("51") ? "clerk" : "stripe";
}

const isStripeKey = (value: string, match: RegExpMatchArray): boolean =>
  value.startsWith("rk_") || classifySecretKey(value.slice(8), match) === "stripe";
const isClerkKey = (value: string, match: RegExpMatchArray): boolean =>
  classifySecretKey(value.slice(8), match) === "clerk";

/** Upstash REST tokens are mixed-case base64; this keeps env-var names and words out. */
function isMixedCaseToken(value: string): boolean {
  return /\d/.test(value) && /[a-z]/.test(value) && /[A-Z]/.test(value);
}

const ASSIGN = `["'\\s:=]{1,6}`;
const DB_USER = `[^\\s:/@'"\`]{1,64}`;
const DB_PASS = `([^\\s@'"\`/]{8,128})`;
const DB_REST = `@[^\\s'"\`]{3,200}`;

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: "SEC-001", name: "AWS access key ID", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/dg, severity: "critical",
    rotateUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
    impact: "spin up servers, read S3 buckets and databases, and run up a cloud bill",
  },
  {
    id: "SEC-002", name: "AWS secret access key",
    regex: new RegExp(`aws_?secret_?(?:access_?)?key${ASSIGN}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])`, "dgi"),
    severity: "critical", rotateUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
    impact: "spin up servers, read S3 buckets and databases, and run up a cloud bill",
  },
  {
    id: "SEC-003", name: "Google Cloud service-account private key",
    regex: /"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----([A-Za-z0-9+/=\s\\]{40,4000}?)-----END/dg,
    severity: "critical", rotateUrl: "https://console.cloud.google.com/iam-admin/serviceaccounts",
    impact: "act as your service account: read storage, databases and anything it has roles for",
  },
  {
    id: "SEC-004", name: "Stripe live secret key", regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,247}(?![A-Za-z0-9])/dg,
    validate: isStripeKey, severity: "critical",
    rotateUrl: "https://dashboard.stripe.com/apikeys",
    impact: "create charges and refunds, read customer and card metadata, and move your money",
  },
  {
    id: "SEC-005", name: "Stripe webhook signing secret", regex: /\bwhsec_[A-Za-z0-9]{24,64}\b/dg, severity: "high",
    rotateUrl: "https://dashboard.stripe.com/webhooks",
    impact: "forge payment webhooks so your app believes an unpaid order was paid",
  },
  {
    id: "SEC-006", name: "OpenRouter API key", regex: /\bsk-or-v1-[a-f0-9]{64}\b/dg, severity: "high",
    rotateUrl: "https://openrouter.ai/keys", impact: "burn through your AI credits",
  },
  {
    id: "SEC-007", name: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{32,200}/dg, severity: "high",
    rotateUrl: "https://console.anthropic.com/settings/keys", impact: "burn through your AI credits",
  },
  {
    id: "SEC-008", name: "OpenAI API key",
    regex: /\bsk-(?!ant-|or-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,200}/dg, severity: "high",
    rotateUrl: "https://platform.openai.com/api-keys", impact: "burn through your AI credits",
    validate: hasDigit,
  },
  {
    id: "SEC-009", name: "Supabase service_role key",
    regex: /\beyJ[A-Za-z0-9_-]{10,400}\.eyJ[A-Za-z0-9_-]{10,800}\.[A-Za-z0-9_-]{10,400}/dg, severity: "critical",
    rotateUrl: "https://supabase.com/dashboard/project/_/settings/api",
    impact: "bypass every Row Level Security policy and read, edit or delete your whole database",
    validate: isServiceRoleJwt,
  },
  {
    id: "SEC-010", name: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/dg, severity: "critical",
    rotateUrl: "https://github.com/settings/tokens", impact: "read or push to your private repositories",
  },
  {
    id: "SEC-011", name: "GitHub fine-grained personal access token", regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}/dg,
    severity: "critical", rotateUrl: "https://github.com/settings/personal-access-tokens",
    impact: "read or push to your private repositories",
  },
  {
    id: "SEC-012", name: "Slack token", regex: /\bxox[abprs]-[A-Za-z0-9-]{10,200}/dg, severity: "high",
    rotateUrl: "https://api.slack.com/apps", impact: "read your workspace messages and post as your bot",
  },
  {
    id: "SEC-013", name: "Slack webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{24}/dg,
    severity: "medium", rotateUrl: "https://api.slack.com/apps", impact: "post any message into your Slack channel",
  },
  {
    id: "SEC-014", name: "Twilio API key", regex: /\bSK[0-9a-f]{32}\b/dg, severity: "high",
    rotateUrl: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
    impact: "send SMS and place calls on your bill",
  },
  {
    id: "SEC-015", name: "Twilio auth token",
    regex: new RegExp(`twilio[\\w .-]{0,30}?(?:token|secret)${ASSIGN}([0-9a-f]{32})(?![0-9a-f])`, "dgi"),
    severity: "high", rotateUrl: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
    impact: "send SMS and place calls on your bill",
  },
  {
    id: "SEC-016", name: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/dg, severity: "high",
    rotateUrl: "https://app.sendgrid.com/settings/api_keys", impact: "send phishing email from your domain",
  },
  {
    id: "SEC-017", name: "Mailgun API key", regex: /\bkey-[0-9a-f]{32}\b/dg, severity: "high",
    rotateUrl: "https://app.mailgun.com/settings/api_security", impact: "send phishing email from your domain",
  },
  {
    id: "SEC-018", name: "Resend API key", regex: /\bre_[A-Za-z0-9]{6,12}_[A-Za-z0-9]{20,40}\b/dg, severity: "high",
    rotateUrl: "https://resend.com/api-keys", impact: "send phishing email from your domain", validate: hasDigit,
  },
  {
    id: "SEC-019", name: "Postmark server token",
    regex: new RegExp(
      `postmark[\\w .-]{0,30}?(?:token|key)${ASSIGN}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`, "dgi",
    ),
    severity: "high", rotateUrl: "https://account.postmarkapp.com/servers", impact: "send phishing email from your domain",
  },
  {
    id: "SEC-020", name: "Discord bot token",
    regex: /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b/dg, severity: "high",
    rotateUrl: "https://discord.com/developers/applications", impact: "take over your bot and every server it is in",
  },
  {
    id: "SEC-021", name: "Discord webhook URL",
    regex: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,80}/dg,
    severity: "medium", rotateUrl: "https://support.discord.com/hc/en-us/articles/228383668",
    impact: "post any message into your Discord channel",
  },
  {
    id: "SEC-022", name: "Telegram bot token", regex: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/dg, severity: "high",
    rotateUrl: "https://t.me/BotFather", impact: "take over your bot and read its messages",
  },
  {
    id: "SEC-023", name: "Hugging Face token", regex: /\bhf_[A-Za-z0-9]{34,40}\b/dg, severity: "high",
    rotateUrl: "https://huggingface.co/settings/tokens", impact: "read your private models and push to your repos",
  },
  {
    id: "SEC-024", name: "Replicate API token", regex: /\br8_[A-Za-z0-9]{37,40}\b/dg, severity: "high",
    rotateUrl: "https://replicate.com/account/api-tokens", impact: "run models on your bill",
  },
  {
    id: "SEC-025", name: "Groq API key", regex: /\bgsk_[A-Za-z0-9]{40,60}\b/dg, severity: "high",
    rotateUrl: "https://console.groq.com/keys", impact: "burn through your AI quota",
  },
  {
    id: "SEC-026", name: "Mistral API key",
    regex: new RegExp(`mistral[\\w .-]{0,30}?(?:key|token|secret)${ASSIGN}([A-Za-z0-9]{32})(?![A-Za-z0-9])`, "dgi"),
    severity: "high", rotateUrl: "https://console.mistral.ai/api-keys", impact: "burn through your AI credits",
  },
  {
    id: "SEC-027", name: "Cohere API key",
    regex: new RegExp(`cohere[\\w .-]{0,30}?(?:key|token|secret)${ASSIGN}([A-Za-z0-9]{40})(?![A-Za-z0-9])`, "dgi"),
    severity: "high", rotateUrl: "https://dashboard.cohere.com/api-keys", impact: "burn through your AI credits",
  },
  {
    id: "SEC-028", name: "Pinecone API key", regex: /\bpcsk_[A-Za-z0-9]{4,10}_[A-Za-z0-9]{40,80}\b/dg, severity: "high",
    rotateUrl: "https://app.pinecone.io", impact: "read, overwrite or delete your vector indexes",
  },
  {
    id: "SEC-029", name: "Clerk secret key", regex: /\bsk_(?:live|test)_[A-Za-z0-9]{40,60}(?![A-Za-z0-9])/dg,
    validate: isClerkKey, severity: "high",
    rotateUrl: "https://dashboard.clerk.com", impact: "list, impersonate and delete your users",
  },
  {
    id: "SEC-030", name: "Private key (PEM)",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----([A-Za-z0-9+/=\s\\]{40,4000}?)-----END/dg,
    severity: "critical", rotateUrl: "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
    impact: "impersonate your server or sign things as you",
  },
  {
    id: "SEC-031", name: "PostgreSQL connection string with password",
    regex: new RegExp(`\\bpostgres(?:ql)?://${DB_USER}:${DB_PASS}${DB_REST}`, "dg"), severity: "critical",
    rotateUrl: "https://www.postgresql.org/docs/current/sql-alterrole.html",
    impact: "connect straight to your database and read, change or wipe everything", validate: isRemoteDbUrl,
  },
  {
    id: "SEC-032", name: "MongoDB connection string with password",
    regex: new RegExp(`\\bmongodb(?:\\+srv)?://${DB_USER}:${DB_PASS}${DB_REST}`, "dg"), severity: "critical",
    rotateUrl: "https://cloud.mongodb.com", impact: "connect straight to your database and read, change or wipe everything",
    validate: isRemoteDbUrl,
  },
  {
    id: "SEC-033", name: "Redis connection string with password",
    regex: new RegExp(`\\brediss?://[^\\s:/@'"\`]{0,64}:${DB_PASS}${DB_REST}`, "dg"), severity: "high",
    rotateUrl: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/",
    impact: "read your cache and sessions, or flush them", validate: isRemoteDbUrl,
  },
  {
    id: "SEC-034", name: "npm access token", regex: /\bnpm_[A-Za-z0-9]{36}\b/dg, severity: "critical",
    rotateUrl: "https://www.npmjs.com/settings/~/tokens", impact: "publish a malicious version of your packages",
  },
  {
    id: "SEC-035", name: "Vercel token",
    regex: new RegExp(`vercel[\\w .-]{0,30}?(?:token|key)${ASSIGN}([A-Za-z0-9]{24})(?![A-Za-z0-9])`, "dgi"),
    severity: "high", rotateUrl: "https://vercel.com/account/tokens", impact: "deploy to and read the env vars of your projects",
  },
  {
    id: "SEC-036", name: "Netlify personal access token", regex: /\bnfp_[A-Za-z0-9]{30,50}\b/dg, severity: "high",
    rotateUrl: "https://app.netlify.com/user/applications", impact: "deploy to and read the env vars of your sites",
  },
  {
    id: "SEC-037", name: "Algolia admin API key",
    regex: new RegExp(`algolia[\\w .-]{0,40}?admin[\\w .-]{0,20}?${ASSIGN}([a-f0-9]{32})(?![a-f0-9])`, "dgi"),
    severity: "high", rotateUrl: "https://dashboard.algolia.com/account/api-keys",
    impact: "edit or delete your search indexes",
  },
  {
    id: "SEC-038", name: "Mapbox secret token", regex: /\bsk\.eyJ[A-Za-z0-9_-]{20,300}\.[A-Za-z0-9_-]{20,100}/dg,
    severity: "medium", rotateUrl: "https://account.mapbox.com/access-tokens/", impact: "use your Mapbox quota and edit your map data",
  },
  {
    id: "SEC-039", name: "Shopify access token", regex: /\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b/dg, severity: "critical",
    rotateUrl: "https://help.shopify.com/en/manual/apps/app-types/custom-apps", impact: "read orders and customers, and change your store",
  },
  {
    id: "SEC-040", name: "Square access token",
    regex: /\b(?:sq0csp-[A-Za-z0-9_-]{43}|sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{56,64})/dg, severity: "critical",
    rotateUrl: "https://developer.squareup.com/apps", impact: "take payments and read customer data",
  },
  {
    id: "SEC-041", name: "DigitalOcean token", regex: /\bdop_v1_[a-f0-9]{64}\b/dg, severity: "critical",
    rotateUrl: "https://cloud.digitalocean.com/account/api/tokens", impact: "create, read and destroy your servers and databases",
  },
  {
    id: "SEC-042", name: "Linear API key", regex: /\blin_api_[A-Za-z0-9]{40}\b/dg, severity: "medium",
    rotateUrl: "https://linear.app/settings/api", impact: "read and edit your issue tracker",
  },
  {
    id: "SEC-043", name: "Sentry auth token", regex: /\bsntrys_[A-Za-z0-9+/=_-]{40,200}/dg, severity: "medium",
    rotateUrl: "https://sentry.io/settings/account/api/auth-tokens/", impact: "read your error reports and project settings",
  },
  {
    id: "SEC-044", name: "Doppler token", regex: /\bdp\.pt\.[A-Za-z0-9]{40,50}\b/dg, severity: "critical",
    rotateUrl: "https://dashboard.doppler.com", impact: "read every secret stored in that Doppler project",
  },
  {
    id: "SEC-045", name: "PlanetScale token", regex: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,64}/dg, severity: "critical",
    rotateUrl: "https://app.planetscale.com", impact: "connect to your database and read or change everything",
  },
  {
    id: "SEC-046", name: "Databricks token", regex: /\bdapi[a-f0-9]{32}\b/dg, severity: "high",
    rotateUrl: "https://docs.databricks.com/aws/en/dev-tools/auth/pat", impact: "run jobs and read data in your workspace",
  },
  {
    id: "SEC-047", name: "Perplexity API key", regex: /\bpplx-[A-Za-z0-9]{48}\b/dg, severity: "high",
    rotateUrl: "https://www.perplexity.ai/settings/api", impact: "burn through your AI credits",
  },
  {
    id: "SEC-048", name: "xAI API key", regex: /\bxai-[A-Za-z0-9]{80}\b/dg, severity: "high",
    rotateUrl: "https://console.x.ai", impact: "burn through your AI credits",
  },
  {
    id: "SEC-049", name: "MySQL connection string with password",
    regex: new RegExp(`\\bmysql2?://${DB_USER}:${DB_PASS}${DB_REST}`, "dg"), severity: "critical",
    rotateUrl: "https://dev.mysql.com/doc/refman/8.0/en/alter-user.html",
    impact: "connect straight to your database and read, change or wipe everything", validate: isRemoteDbUrl,
  },
  {
    id: "SEC-050", name: "Supabase secret API key", regex: /\bsb_secret_[A-Za-z0-9_-]{20,64}(?![A-Za-z0-9_-])/dg,
    severity: "critical", rotateUrl: "https://supabase.com/dashboard/project/_/settings/api-keys",
    impact: "bypass every Row Level Security policy and read, edit or delete your whole database",
  },
  {
    id: "SEC-051", name: "Supabase personal access token", regex: /\bsbp_[a-f0-9]{40}(?![A-Za-z0-9])/dg,
    severity: "critical", rotateUrl: "https://supabase.com/dashboard/account/tokens",
    impact: "manage every project in your Supabase account through the management API",
  },
  {
    id: "SEC-052", name: "Google OAuth client secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/dg,
    severity: "high", rotateUrl: "https://console.cloud.google.com/apis/credentials",
    impact: "impersonate your app in Google sign-in and exchange stolen authorization codes",
  },
  {
    id: "SEC-053", name: "Upstash Redis REST token",
    regex: new RegExp(`UPSTASH[A-Z0-9_]{0,40}TOKEN${ASSIGN}([A-Za-z0-9+/_-]{30,120}={0,2})(?![A-Za-z0-9+/=_-])`, "dgi"),
    severity: "high", rotateUrl: "https://console.upstash.com",
    impact: "read, overwrite or flush your Redis data", validate: isMixedCaseToken,
  },
  {
    id: "SEC-054", name: "Neon API key", regex: /\bnapi_[a-z0-9]{40,80}(?![A-Za-z0-9_])/dg, severity: "high",
    rotateUrl: "https://console.neon.tech/app/settings/api-keys",
    impact: "create, change and delete your Neon projects and databases", validate: hasDigit,
  },
  {
    id: "SEC-055", name: "Render API key", regex: /\brnd_[A-Za-z0-9]{24,48}(?![A-Za-z0-9_])/dg, severity: "high",
    rotateUrl: "https://dashboard.render.com/u/settings#api-keys",
    impact: "deploy to, read the env vars of and delete your Render services", validate: hasDigit,
  },
  {
    id: "SEC-056", name: "Fly.io access token", regex: /\b(?:fo1_[A-Za-z0-9_-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,2000}={0,3}|fm2_[A-Za-z0-9+/]{100,2000}={0,3})(?![A-Za-z0-9_-])/dg, severity: "high",
    rotateUrl: "https://fly.io/user/personal_access_tokens",
    impact: "deploy to and read the secrets of your Fly.io apps",
  },
  {
    id: "SEC-057", name: "Brevo (Sendinblue) API key", regex: /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}(?![A-Za-z0-9])/dg,
    severity: "high", rotateUrl: "https://app.brevo.com/settings/keys/api",
    impact: "send phishing email from your domain and read your contact lists",
  },
  {
    id: "SEC-058", name: "Lemon Squeezy API key",
    regex: new RegExp(
      `lemon_?squeezy[\\w .-]{0,30}?(?:key|token)${ASSIGN}(eyJ[A-Za-z0-9_-]{10,300}\\.eyJ[A-Za-z0-9_-]{100,2500}\\.[A-Za-z0-9_-]{80,1000})`,
      "dgi",
    ),
    severity: "high", rotateUrl: "https://app.lemonsqueezy.com/settings/api",
    impact: "read your orders and customers and change your store and subscriptions",
  },
  {
    id: "SEC-059", name: "Google AI (Gemini) API key",
    regex: new RegExp(
      `(?:gemini_?api_?key|google_?api_?key|google_?generative_?ai_?api_?key|google_?ai_?api_?key)${ASSIGN}(AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])`,
      "dgi",
    ),
    severity: "high", rotateUrl: "https://aistudio.google.com/apikey",
    impact: "burn through your AI quota and bill",
  },
];

export const DEFAULT_IMPACT = "use your account on that service, run up charges and read or change your data";
