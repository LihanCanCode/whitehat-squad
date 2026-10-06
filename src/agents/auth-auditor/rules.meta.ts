import type { RuleMeta } from "../../rules/types.js";

const AGENT = "auth-auditor";
const MODES = ["static"] as const;

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
const BASE_RULES: readonly RuleMeta[] = [
  {
    id: "AUTH-001",
    agent: AGENT,
    title: "Route protection exists only in the browser",
    severity: "high",
    cwe: "CWE-602",
    owasp: "A01",
    summary:
      "A page redirects logged-out visitors from client-side code while the project has no middleware or server-side session check. Browser redirects are cosmetic: anyone can call the API or database directly, so the protected data is reachable without logging in.",
    fix: "Enforce the session on the server (middleware plus per-handler checks) and keep the client redirect only for UX.",
    modes: MODES,
    tags: ["authz", "nextjs"],
  },
  {
    id: "AUTH-002",
    agent: AGENT,
    title: "Endpoint reads or writes data without checking who is calling",
    severity: "high",
    cwe: "CWE-306",
    owasp: "A01",
    summary:
      "A route handler or server action touches the database but never checks a session or token. Any logged-out visitor can call it directly and read, change or delete other users' rows.",
    fix: "Authenticate the caller at the top of the handler, reject anonymous requests with 401, and scope queries to the authenticated user.",
    modes: MODES,
    tags: ["authn", "api"],
  },
  {
    id: "AUTH-003",
    agent: AGENT,
    title: "Record is looked up by a caller-supplied id with no ownership check (IDOR)",
    severity: "high",
    cwe: "CWE-639",
    owasp: "A01",
    summary:
      "An id taken from the request is used to fetch, change or delete a record without checking that it belongs to the logged-in user. Any signed-in user can swap in someone else's id and read or destroy their data.",
    fix: "Filter by the authenticated user's id (for example .eq(\"user_id\", user.id) or userId in a Prisma where clause) or rely on a correct RLS policy, and return 404 when nothing matches.",
    modes: MODES,
    tags: ["idor", "authz"],
  },
  {
    id: "AUTH-004",
    agent: AGENT,
    title: "JWT is decoded, unsigned or signed with a hard-coded secret",
    severity: "high",
    cwe: "CWE-345",
    owasp: "A02",
    summary:
      "JWT handling that does not verify the signature (jwt.decode used for authorization), accepts the none algorithm (critical), or uses a secret written in source code lets anyone forge tokens for any user or role.",
    fix: "Use jwt.verify or jose jwtVerify with a secret from the environment and a pinned algorithm allow-list that never contains none.",
    modes: MODES,
    tags: ["jwt", "crypto"],
  },
  {
    id: "AUTH-005",
    agent: AGENT,
    title: "Access decision based on a value the user controls",
    severity: "high",
    cwe: "CWE-602",
    owasp: "A01",
    summary:
      "A role, admin flag or plan is read from localStorage, sessionStorage or a plain cookie and used to gate access. Users can edit these in dev tools and promote themselves or unlock paid features.",
    fix: "Derive roles from the verified server-side session or a database lookup and treat client storage as display-only.",
    modes: MODES,
    tags: ["authz", "client-trust"],
  },
  {
    id: "AUTH-006",
    agent: AGENT,
    title: "Stripe webhook trusts the request body without verifying the signature",
    severity: "critical",
    cwe: "CWE-345",
    owasp: "A08",
    summary:
      "A webhook acts on Stripe event types after merely parsing the request body. Anyone can POST a fake checkout.session.completed event and obtain a free upgrade, credits or a paid order.",
    fix: "Read the raw body and verify it with stripe.webhooks.constructEvent and the stripe-signature header before acting; return 400 on failure.",
    modes: MODES,
    tags: ["stripe", "webhook", "payments"],
  },
  {
    id: "AUTH-007",
    agent: AGENT,
    title: "Supabase service_role key used in client-side code",
    severity: "critical",
    cwe: "CWE-798",
    owasp: "A05",
    summary:
      "The service_role key bypasses all Row Level Security. Code that ships to the browser exposes it, so any visitor can read, modify and delete every row in the database.",
    fix: "Use the anon key in client code, keep service_role in server-only modules, never prefix it with NEXT_PUBLIC_ or VITE_, and rotate the exposed key.",
    modes: MODES,
    tags: ["supabase", "secrets"],
  },
];

interface NewRule {
  readonly id: string;
  readonly title: string;
  readonly severity: RuleMeta["severity"];
  readonly cwe: string;
  readonly owasp: string;
  readonly summary: string;
  readonly fix: string;
  readonly tags: readonly string[];
}

const NEW_RULES: readonly NewRule[] = [
  { id: "AUTH-008", title: "Server code trusts supabase.auth.getSession() for authorization", severity: "high", cwe: "CWE-345", owasp: "A07",
    summary: "getSession() reads the session from the cookie and is not re-validated on the server, so a forged cookie is believed. Using session.user.id without getUser() or getClaims() in the same function lets an attacker impersonate users.",
    fix: "Call supabase.auth.getUser() (or getClaims()) on the server and authorize with that result.", tags: ["supabase", "authn"] },
  { id: "AUTH-009", title: "Authorization decision uses user_metadata, which users can edit", severity: "critical", cwe: "CWE-807", owasp: "A01",
    summary: "Supabase user_metadata can be changed by the signed-in user. Checking user_metadata.role, is_admin or plan in a condition lets anyone promote themselves or unlock paid features. app_metadata is safe.",
    fix: "Read roles and plans from app_metadata or a table protected by RLS.", tags: ["supabase", "authz", "client-trust"] },
  { id: "AUTH-010", title: "Request body is written straight into the database (mass assignment)", severity: "high", cwe: "CWE-915", owasp: "A01",
    summary: "The whole request object is passed to an ORM write (Prisma data, Drizzle values/set, Mongoose create/update, Supabase insert/update, Object.assign), so callers choose every column including role, is_admin, credits or user_id.",
    fix: "Validate with a schema and copy only the fields users may set.", tags: ["mass-assignment", "orm"] },
  { id: "AUTH-011", title: "Payment amount is client-controlled or a success page grants access unverified", severity: "critical", cwe: "CWE-472", owasp: "A04",
    summary: "A Stripe checkout, payment intent or price is created with an amount taken from the request (critical), or a success page upgrades the account from session_id without retrieving the checkout session or relying on a webhook (high).",
    fix: "Decide prices on the server and fulfil from a verified webhook or after checkout.sessions.retrieve confirms payment.", tags: ["stripe", "payments"] },
  { id: "AUTH-012", title: "Secret token generated with a predictable random source", severity: "high", cwe: "CWE-338", owasp: "A02",
    summary: "Math.random() or Date.now() is used to produce a token, otp, code, secret, nonce, salt or session id in server code. These values are predictable and can be guessed.",
    fix: "Use crypto.randomBytes, crypto.randomUUID or crypto.randomInt.", tags: ["crypto", "tokens"] },
  { id: "AUTH-013", title: "Weak password hashing or plaintext password handling", severity: "high", cwe: "CWE-916", owasp: "A02",
    summary: "Passwords hashed with md5/sha1/sha256, bcrypt with a cost below 10, compared with === or stored with no hashing are exposed when the database leaks.",
    fix: "Use bcrypt (cost 12+), argon2id or scrypt and compare with the library function.", tags: ["passwords", "crypto"] },
  { id: "AUTH-014", title: "Login or recovery endpoint has no rate limiting", severity: "medium", cwe: "CWE-307", owasp: "A07",
    summary: "Login, signup, password reset, OTP and magic-link handlers with no rate limiter allow brute force and email flooding. Confidence is lower when a hosted auth provider throttles requests.",
    fix: "Rate limit by IP and account and return 429 when exceeded.", tags: ["rate-limit", "authn"] },
  { id: "AUTH-015", title: "Debug, seed, cron or admin route is reachable without authentication", severity: "high", cwe: "CWE-306", owasp: "A01",
    summary: "A route under debug, seed, test, dev, internal, migrate, reset-db, admin or cron has no auth check, shared secret or production guard. It is critical when it runs migrations, deletes data, executes commands or returns process.env.",
    fix: "Require an admin session or CRON_SECRET and disable debug routes in production.", tags: ["authn", "ops-routes"] },
  { id: "AUTH-016", title: "Authentication check is inverted", severity: "high", cwe: "CWE-863", owasp: "A01",
    summary: "The code returns 401/403 when a user IS present (if (user) return ...), locking out real users and letting anonymous callers through.",
    fix: "Negate the condition and test that an anonymous request gets 401.", tags: ["authn", "logic"] },
  { id: "AUTH-017", title: "Insecure authentication cookie, token expiry or token storage", severity: "medium", cwe: "CWE-1004", owasp: "A07",
    summary: "Auth cookies without httpOnly or with secure off, jwt.sign without expiresIn, and tokens saved in localStorage/sessionStorage (refresh tokens are high) make session theft easier and sessions immortal.",
    fix: "Use httpOnly, secure, sameSite cookies, short token lifetimes and no web storage for tokens.", tags: ["cookies", "jwt", "sessions"] },
  { id: "AUTH-018", title: "OAuth accounts are linked by email without verification", severity: "high", cwe: "CWE-287", owasp: "A07",
    summary: "allowDangerousEmailAccountLinking: true attaches any provider sign-in to an existing account with the same email, enabling account takeover through an unverified provider email.",
    fix: "Remove the option or restrict linking to providers with verified emails.", tags: ["oauth", "nextauth"] },
  { id: "AUTH-019", title: "Password-reset or invite link is built from the Host header", severity: "medium", cwe: "CWE-640", owasp: "A07",
    summary: "A reset, invite or magic link uses a host or origin read from request headers, so an attacker can make the emailed link point at their site and capture the token.",
    fix: "Build links from a fixed site URL in configuration.", tags: ["password-reset", "host-header"] },
];

export const RULES: readonly RuleMeta[] = [
  ...BASE_RULES,
  ...NEW_RULES.map((r): RuleMeta => ({ ...r, agent: AGENT, modes: MODES })),
];
