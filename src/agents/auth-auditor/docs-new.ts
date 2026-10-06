import { OWASP, type Doc } from "./docs-core.js";

const SESSION_MGMT = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html";
const PASSWORDS = "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html";
const MASS = "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html";
const API3 = "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/";

/** Documentation for AUTH-008 .. AUTH-019 (title, severity, wording and the fix patch per rule or variant). */
export const NEW_DOCS: Record<string, Doc> = {
  "AUTH-008": {
    title: "Server code trusts supabase.auth.getSession() for authorization",
    severity: "high",
    cwe: "CWE-345",
    explanation:
      "getSession() only reads the session out of the cookie; on the server it is not re-validated with Supabase, so a forged or stale cookie is believed. Using session.user.id to decide who the caller is lets an attacker impersonate another user.",
    summary: "Call supabase.auth.getUser() (or getClaims()) on the server and use that result for authorization.",
    snippet: `const { data: { user }, error } = await supabase.auth.getUser();
if (error || !user) return Response.json({ error: "unauthorized" }, { status: 401 });
// use user.id, never session.user.id from getSession()`,
    instruction:
      "this server code authorizes with supabase.auth.getSession(), which is not validated server-side. Replace it with supabase.auth.getUser() (or getClaims()) and use that user for every ownership check.",
    refs: ["https://supabase.com/docs/reference/javascript/auth-getsession", "https://supabase.com/docs/guides/auth/server-side/nextjs"],
  },
  "AUTH-009": {
    title: "Authorization decision uses user_metadata, which users can edit",
    severity: "critical",
    cwe: "CWE-807",
    explanation:
      "user_metadata can be changed by the signed-in user themselves with supabase.auth.updateUser(). Checking user_metadata.role, is_admin or plan means anyone can promote themselves to admin or unlock paid features with one API call.",
    summary: "Read roles and plans from app_metadata (only writable with the service role) or from a database table protected by RLS.",
    snippet: `// app_metadata is writable only by your server
if (user.app_metadata?.role !== "admin") return new Response(null, { status: 403 });`,
    instruction:
      "an access decision reads user_metadata, which the user can modify. Move the role/plan to app_metadata (set via the admin API) or a protected table, and check that server-side instead.",
    refs: ["https://supabase.com/docs/guides/auth/managing-user-data", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
  },
  "AUTH-010": {
    title: "Request body is written straight into the database (mass assignment)",
    severity: "high",
    cwe: "CWE-915",
    explanation:
      "The whole request object is passed to the ORM, so the caller chooses every column, not just the ones your form shows. They can add fields such as role, is_admin, credits or user_id and overwrite data they should never control.",
    summary: "Validate with a schema and copy only the fields users may set; never spread the body into a write.",
    snippet: `const input = z.object({ name: z.string().max(100), bio: z.string().max(500) }).parse(await req.json());
await prisma.user.update({ where: { id: user.id }, data: { name: input.name, bio: input.bio } });`,
    instruction:
      "the request body is passed whole to a database write. Parse it with a zod schema that lists only user-editable fields (or pick() them explicitly) and write only those fields; set ownership columns from the session.",
    refs: [MASS, API3],
  },
  "AUTH-010:sensitive": {
    title: "Request body is written straight into a table that has privilege columns",
    severity: "high",
    cwe: "CWE-915",
    explanation:
      "The whole request object is passed to the ORM and the target table has privilege-bearing columns (such as role, is_admin or credits), so a normal user can send those fields and grant themselves admin rights or free credits.",
    summary: "Whitelist the editable fields; keep privilege columns out of anything the client can set.",
    snippet: `const { name, bio } = schema.parse(await req.json());
await db.update(users).set({ name, bio }).where(eq(users.id, user.id));`,
    instruction:
      "the request body is written whole into a table that has role/admin/credit columns. Whitelist the fields a user may edit, and update privilege columns only from trusted server code.",
    refs: [MASS, API3],
  },
  "AUTH-011:tamper": {
    title: "Payment amount is taken from the request",
    severity: "critical",
    cwe: "CWE-472",
    explanation:
      "The price or amount sent to Stripe comes from request input, so a buyer can edit it in dev tools and pay 1 cent for anything. Prices must be decided on the server.",
    summary: "Look the price up on the server (database or Stripe Price id) and never accept an amount from the client.",
    snippet: `const product = await db.product.findUnique({ where: { id: body.productId } });
await stripe.checkout.sessions.create({
  mode: "payment",
  line_items: [{ price: product.stripePriceId, quantity: 1 }],
});`,
    instruction:
      "the amount/price given to Stripe is read from the request. Accept only a product id, load the price from your database or a Stripe Price id on the server, and pass that to Stripe.",
    refs: ["https://docs.stripe.com/payments/checkout/custom-success-page", "https://cwe.mitre.org/data/definitions/472.html"],
  },
  "AUTH-011:success": {
    title: "Success page grants access from session_id without verifying the payment",
    severity: "high",
    cwe: "CWE-345",
    explanation:
      "This code reads session_id from the URL and upgrades the account (plan, credits or premium flag) without asking Stripe whether that checkout was actually paid. Anyone can open the success URL with any value and get the upgrade for free.",
    summary: "Fulfil from the verified webhook, or retrieve the Checkout Session from Stripe and check payment_status first.",
    snippet: `const session = await stripe.checkout.sessions.retrieve(sessionId);
if (session.payment_status !== "paid") return redirect("/pricing");
// grant access only after this check, ideally from the checkout.session.completed webhook`,
    instruction:
      "this code upgrades the user based on a session_id from the request. Call stripe.checkout.sessions.retrieve(session_id), verify payment_status === 'paid' and that it belongs to the current user, or move the grant into a signature-verified webhook.",
    refs: ["https://docs.stripe.com/payments/checkout/fulfill-orders", "https://docs.stripe.com/webhooks#verify-events"],
  },
  "AUTH-012": {
    title: "Secret token generated with a predictable random source",
    severity: "high",
    cwe: "CWE-338",
    explanation:
      "Math.random() and Date.now() are predictable. A token, code or secret built from them can be guessed or reproduced by an attacker, which breaks password resets, invites, OTP codes and session ids.",
    summary: "Generate secrets with crypto.randomBytes / crypto.randomUUID / crypto.randomInt.",
    snippet: `import { randomBytes, randomInt } from "node:crypto";
const token = randomBytes(32).toString("hex");
const otp = String(randomInt(100000, 1000000));`,
    instruction:
      "a security-sensitive value is generated with Math.random() or Date.now(). Replace it with crypto.randomBytes(32).toString('hex') (tokens) or crypto.randomInt (numeric codes) and invalidate values issued the old way.",
    refs: ["https://cwe.mitre.org/data/definitions/338.html", SESSION_MGMT],
  },
  "AUTH-013:hash": {
    title: "Password hashed with a fast general-purpose hash",
    severity: "high",
    cwe: "CWE-916",
    explanation:
      "MD5, SHA-1 and SHA-256 are designed to be fast, so attackers can test billions of guesses per second against a leaked database. Passwords need a slow, salted password hash.",
    summary: "Use argon2id, scrypt or bcrypt (cost 12 or more) for passwords.",
    snippet: `import bcrypt from "bcryptjs";
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(password, hash);`,
    instruction:
      "a password is hashed with md5/sha1/sha256. Switch to bcrypt (cost 12+), argon2id or scrypt and rehash existing passwords on the next successful login.",
    refs: [PASSWORDS, "https://cwe.mitre.org/data/definitions/916.html"],
  },
  "AUTH-013:rounds": {
    title: "bcrypt cost factor is too low",
    severity: "high",
    cwe: "CWE-916",
    explanation: "A bcrypt cost below 10 hashes passwords too quickly, so stolen hashes can be cracked far faster than intended.",
    summary: "Use a cost factor of 12 or higher.",
    snippet: `const hash = await bcrypt.hash(password, 12);`,
    instruction: "the bcrypt cost/rounds value is below 10. Raise it to 12 (or higher) and rehash passwords on next login.",
    refs: [PASSWORDS],
  },
  "AUTH-013:plaintext": {
    title: "Password stored or compared in plain text",
    severity: "high",
    cwe: "CWE-256",
    explanation:
      "The password is compared with === or saved as-is with no hashing, so anyone who reads the database (or a backup) can sign in as every user.",
    summary: "Store only a bcrypt/argon2 hash and compare with the library's compare function.",
    snippet: `const passwordHash = await bcrypt.hash(body.password, 12);
await db.user.create({ data: { email: body.email, passwordHash } });
// login
const ok = await bcrypt.compare(password, user.passwordHash);`,
    instruction:
      "passwords are stored or compared in plain text. Hash on registration with bcrypt/argon2, store only the hash, and compare with bcrypt.compare; force a password reset for existing users.",
    refs: [PASSWORDS, "https://cwe.mitre.org/data/definitions/256.html"],
  },
  "AUTH-014": {
    title: "Login or recovery endpoint has no rate limiting",
    severity: "medium",
    cwe: "CWE-307",
    explanation:
      "Sign-in, sign-up, password-reset and OTP endpoints with no rate limit let a script try thousands of passwords or six-digit codes per minute, or flood users with emails.",
    summary: "Rate limit by IP and by account (for example with Upstash Ratelimit) and lock out repeated failures.",
    snippet: `import { Ratelimit } from "@upstash/ratelimit";
const limiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, "1 m") });
const { success } = await limiter.limit(ip);
if (!success) return Response.json({ error: "too many attempts" }, { status: 429 });`,
    instruction:
      "this authentication endpoint has no rate limiting. Add an IP + account based limiter (e.g. @upstash/ratelimit) before the credential check and return 429 when exceeded.",
    refs: ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks", "https://cwe.mitre.org/data/definitions/307.html"],
  },
  "AUTH-014:hosted": {
    title: "Login or recovery endpoint has no rate limiting of its own",
    severity: "low",
    cwe: "CWE-307",
    explanation:
      "This endpoint forwards credentials to a hosted auth provider, which applies its own per-IP limits, so brute force is slowed. The provider limits are global defaults, though: your endpoint can still be used to flood one user with reset or OTP emails, or to burn the project's shared email quota.",
    summary: "Check the provider's auth rate limits fit your app, and add a per-account limiter for reset and OTP requests.",
    snippet: `const { success } = await limiter.limit(\`reset:\${email}\`);
if (!success) return Response.json({ error: "too many attempts" }, { status: 429 });`,
    instruction:
      "this endpoint relies on the auth provider's default rate limits. Add a per-account limiter for password reset / OTP / magic-link requests and confirm the provider's auth rate limits in its dashboard.",
    refs: ["https://supabase.com/docs/guides/auth/rate-limits", "https://cwe.mitre.org/data/definitions/307.html"],
  },
  "AUTH-015": {
    title: "Debug, seed, cron or admin route is reachable without authentication",
    severity: "high",
    cwe: "CWE-306",
    explanation:
      "Routes meant for development or operations (debug, seed, test, migrate, cron, admin) were deployed with no auth check, no shared secret and no production guard. Anyone who guesses the URL can run them.",
    summary: "Require a session or shared secret, or disable the route in production.",
    snippet: `if (process.env.NODE_ENV === "production") return new Response(null, { status: 404 });
// or, for cron:
if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response(null, { status: 401 });`,
    instruction:
      "this operational route has no authentication. Require an admin session or a CRON_SECRET bearer check, and return 404 in production for debug/seed routes.",
    refs: [OWASP, "https://vercel.com/docs/cron-jobs/manage-cron-jobs#securing-cron-jobs"],
  },
  "AUTH-015:critical": {
    title: "Destructive or secret-leaking operations route is reachable without authentication",
    severity: "critical",
    cwe: "CWE-306",
    explanation:
      "A debug, seed, migrate, cron or admin route with no auth check runs migrations, deletes data, executes commands or returns process.env. Any visitor can wipe or dump the application.",
    summary: "Remove the route from production or put it behind an admin session / shared secret immediately.",
    snippet: `if (process.env.NODE_ENV === "production") return new Response(null, { status: 404 });
const user = await getCurrentUser();
if (user?.role !== "admin") return new Response(null, { status: 403 });`,
    instruction:
      "this unauthenticated operations route migrates, deletes, executes commands or exposes process.env. Delete it from production builds or require an admin session and a shared secret; rotate any secret it may have exposed.",
    refs: [OWASP, "https://cwe.mitre.org/data/definitions/306.html"],
  },
  "AUTH-016": {
    title: "Authentication check is inverted",
    severity: "high",
    cwe: "CWE-863",
    explanation:
      "The code rejects the request with 401/403 when a user IS signed in (if (user) return ...), which is the opposite of what is intended. Logged-in users are locked out and anonymous callers fall through to the protected logic.",
    summary: "Negate the condition: reject when there is no user.",
    snippet: `if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });`,
    instruction:
      "the auth check rejects authenticated users and lets anonymous ones through. Change `if (user)` to `if (!user)` and add a test that an anonymous request gets 401.",
    refs: [OWASP, "https://cwe.mitre.org/data/definitions/863.html"],
  },
  "AUTH-017:cookie": {
    title: "Authentication cookie is readable by JavaScript or sent over HTTP",
    severity: "medium",
    cwe: "CWE-1004",
    explanation:
      "A session or token cookie is set without httpOnly: true (or with httpOnly/secure turned off), so any XSS can steal it, or it can be sniffed on plain HTTP.",
    summary: "Set httpOnly: true, secure in production, sameSite and a max age.",
    snippet: `cookies().set("session", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 60 * 60 * 24 * 7 });`,
    instruction:
      "this authentication cookie is missing httpOnly: true (or disables httpOnly/secure). Set httpOnly: true, secure: true in production, sameSite: 'lax' and a maxAge.",
    refs: [SESSION_MGMT, "https://cwe.mitre.org/data/definitions/1004.html"],
  },
  "AUTH-017:jwt-expiry": {
    title: "JWT is issued without an expiry",
    severity: "medium",
    cwe: "CWE-613",
    explanation:
      "A token created without expiresIn stays valid forever. If it leaks, the attacker keeps access indefinitely and you cannot rotate it short of changing the secret for everyone.",
    summary: "Always set a short expiresIn and use refresh tokens for longer sessions.",
    snippet: `jwt.sign({ sub: user.id }, process.env.JWT_SECRET!, { algorithm: "HS256", expiresIn: "15m" });`,
    instruction: "this token is issued without an expiry. Add expiresIn (for example '15m' or '1h') and issue refresh tokens for longer sessions.",
    refs: ["https://datatracker.ietf.org/doc/html/rfc8725", "https://cwe.mitre.org/data/definitions/613.html"],
  },
  "AUTH-017:storage": {
    title: "Auth token stored in localStorage or sessionStorage",
    severity: "medium",
    cwe: "CWE-922",
    explanation:
      "Anything in web storage can be read by any script on the page, so a single XSS bug exposes every user's token. An httpOnly cookie is not readable from JavaScript.",
    summary: "Keep tokens in httpOnly, secure, sameSite cookies set by the server.",
    snippet: `// server
cookies().set("session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });`,
    instruction:
      "an authentication token is saved to localStorage/sessionStorage. Have the server set it as an httpOnly, secure, sameSite cookie and remove the storage write.",
    refs: [SESSION_MGMT, "https://cwe.mitre.org/data/definitions/922.html"],
  },
  "AUTH-017:refresh": {
    title: "Refresh token stored in localStorage or sessionStorage",
    severity: "high",
    cwe: "CWE-922",
    explanation:
      "Refresh tokens are long-lived. Storing one in web storage means a single XSS bug hands an attacker lasting access to the account, not just a short session.",
    summary: "Keep refresh tokens in httpOnly, secure, sameSite cookies and rotate them on use.",
    snippet: `cookies().set("refresh_token", refresh, { httpOnly: true, secure: true, sameSite: "strict", path: "/api/auth/refresh" });`,
    instruction:
      "a refresh token is written to web storage. Move it to an httpOnly, secure, sameSite=strict cookie scoped to the refresh endpoint and rotate it on every use.",
    refs: [SESSION_MGMT, "https://cwe.mitre.org/data/definitions/922.html"],
  },
  "AUTH-018": {
    title: "OAuth accounts are linked by email without verification",
    severity: "high",
    cwe: "CWE-287",
    explanation:
      "allowDangerousEmailAccountLinking lets a sign-in from any provider attach to an existing account that has the same email. An attacker who registers that email at a provider that does not verify it takes over the victim's account.",
    summary: "Remove the option, or only link providers that guarantee verified emails and require re-authentication.",
    snippet: `GitHub({ clientId, clientSecret }) // no allowDangerousEmailAccountLinking`,
    instruction:
      "remove allowDangerousEmailAccountLinking: true. If linking is needed, restrict it to providers with verified emails and ask the user to confirm via their existing sign-in method.",
    refs: ["https://next-auth.js.org/configuration/providers/oauth#allowdangerousemailaccountlinking", "https://authjs.dev/concepts/faq#security"],
  },
  "AUTH-019": {
    title: "Password-reset or invite link is built from the Host header",
    severity: "medium",
    cwe: "CWE-640",
    explanation:
      "The link emailed to the user uses a hostname taken from the request headers. An attacker can send a reset request for the victim with a forged Host or Origin header and the victim receives a link that points at the attacker's site, leaking the reset token.",
    summary: "Build links from a fixed site URL in configuration (for example NEXT_PUBLIC_SITE_URL).",
    snippet: `const siteUrl = process.env.NEXT_PUBLIC_SITE_URL!;
await supabase.auth.resetPasswordForEmail(email, { redirectTo: \`\${siteUrl}/auth/reset\` });`,
    instruction:
      "the emailed link uses a host/origin from request headers. Replace it with a fixed base URL from an environment variable validated at startup.",
    refs: ["https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning", "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"],
  },
};
