import type { Severity } from "../../core/types.js";

export interface Doc {
  readonly title: string;
  readonly severity: Severity;
  readonly cwe: string;
  readonly explanation: string;
  readonly summary: string;
  readonly snippet: string;
  readonly instruction: string;
  readonly refs: readonly string[];
}

export const OWASP = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/";
export const NEXT_AUTH = "https://nextjs.org/docs/app/building-your-application/authentication";

const SERVER_CHECK = `const supabase = createClient();
const { data: { user } } = await supabase.auth.getUser();
if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });`;

export const CORE_DOCS: Record<string, Doc> = {
  "AUTH-001": {
    title: "Route protection exists only in the browser",
    severity: "high",
    cwe: "CWE-602",
    explanation:
      "This page redirects logged-out visitors from client-side code, and the project has no middleware or server-side session check. Redirects in the browser are cosmetic: anyone can disable JavaScript, call your API or database directly, or read the shipped bundle, so the protected data is reachable without logging in.",
    summary: "Enforce the session on the server (middleware plus per-handler checks), keep the client redirect only for UX.",
    snippet: `// middleware.ts (Supabase SSR)
import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
export async function middleware(req: NextRequest) {
  const res = NextResponse.next();
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => req.cookies.getAll(), setAll: (c) => c.forEach(({ name, value }) => res.cookies.set(name, value)) },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.redirect(new URL("/login", req.url));
  return res;
}
export const config = { matcher: ["/dashboard/:path*"] };`,
    instruction:
      "this page only redirects unauthenticated users in the browser. Add a middleware.ts that validates the session server-side (supabase.auth.getUser) and also check the session inside every API route / server action that serves this page's data. Do not rely on client redirects.",
    refs: [NEXT_AUTH, "https://supabase.com/docs/guides/auth/server-side/nextjs"],
  },
  "AUTH-002": {
    title: "Endpoint reads or writes data without checking who is calling",
    severity: "high",
    cwe: "CWE-306",
    explanation:
      "This handler touches your database but never checks a session or token. Any logged-out visitor can call the URL directly (curl is enough) and read, change or delete other users' rows.",
    summary: "Authenticate the caller at the top of the handler and reject anonymous requests with 401.",
    snippet: SERVER_CHECK,
    instruction:
      "this route handler / server action accesses data but never verifies the caller. Add a session check at the top (supabase.auth.getUser, auth(), getServerSession), return 401 when absent, and scope every query to the authenticated user.",
    refs: [OWASP, NEXT_AUTH],
  },
  "AUTH-003": {
    title: "Record is looked up by a caller-supplied id with no ownership check (IDOR)",
    severity: "high",
    cwe: "CWE-639",
    explanation:
      "The id comes straight from the request and is used to fetch, change or delete a record without checking the record belongs to the logged-in user. Any signed-in user can change the id to someone else's and read or destroy their data.",
    summary: "Add an ownership filter using the authenticated user's id (or rely on a correct RLS policy).",
    snippet: `// Supabase
.eq("id", id).eq("user_id", user.id)
// Prisma
where: { id, userId: session.user.id }`,
    instruction:
      "the id taken from the request is used in a database lookup/update/delete without an ownership filter. Add `.eq('user_id', user.id)` (Supabase) or `userId: session.user.id` in the where clause (Prisma), and return 404 when nothing matches.",
    refs: ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html", OWASP],
  },
  "AUTH-004:decode": {
    title: "JWT is decoded without verifying its signature",
    severity: "high",
    cwe: "CWE-345",
    explanation:
      "jwt.decode only base64-decodes the token; it never checks the signature. Anyone can forge a token claiming to be an admin or another user and this code will believe it.",
    summary: "Use jwt.verify (or jose jwtVerify) with a secret from the environment and a pinned algorithm.",
    snippet: `const claims = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ["HS256"] });`,
    instruction:
      "this code uses a decoded JWT for authorization without verifying the signature. Replace decode with jwt.verify / jose jwtVerify using a secret from process.env and an explicit algorithms allow-list.",
    refs: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html", "https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback"],
  },
  "AUTH-004:none": {
    title: "JWT verification accepts the 'none' algorithm",
    severity: "critical",
    cwe: "CWE-347",
    explanation:
      "Allowing the 'none' algorithm means a token with no signature is accepted. Any visitor can hand-write a token for any user or role and be treated as authenticated.",
    summary: "Pin an explicit algorithm allow-list that never contains 'none'.",
    snippet: `jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ["HS256"] });`,
    instruction:
      "remove 'none' from the JWT algorithms list and pin an explicit allow-list such as ['HS256'] with a secret from process.env.",
    refs: ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
  },
  "AUTH-004:secret": {
    title: "JWT signed or verified with a hard-coded secret",
    severity: "high",
    cwe: "CWE-798",
    explanation:
      "The signing secret is written in source code. Anyone who can read the repository or the bundle can mint valid tokens for any user, including admins.",
    summary: "Move the secret to an environment variable, rotate it, and fail fast when it is missing.",
    snippet: `const secret = process.env.JWT_SECRET;
if (!secret) throw new Error("JWT_SECRET is not set");
jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "1h" });`,
    instruction:
      "a JWT secret is hard-coded. Move it to process.env.JWT_SECRET (throw at startup if missing), rotate the exposed secret, and invalidate tokens issued with it.",
    refs: ["https://cwe.mitre.org/data/definitions/798.html"],
  },
  "AUTH-005": {
    title: "Access decision based on a value the user controls",
    severity: "high",
    cwe: "CWE-602",
    explanation:
      "A role, admin flag or plan is read from localStorage, sessionStorage or a plain cookie and used to gate access. Users can edit these in their browser's dev tools and promote themselves to admin or unlock paid features.",
    summary: "Derive roles from the verified server-side session or a database lookup; treat client storage as display-only.",
    snippet: `// server-side
const { data: profile } = await supabase.from("profiles").select("role").eq("id", user.id).single();
if (profile?.role !== "admin") return new Response(null, { status: 403 });`,
    instruction:
      "access is gated on a role/plan read from client-controlled storage. Remove that check and enforce the role server-side from the authenticated session (profiles table or JWT app_metadata) in every route that needs it.",
    refs: [OWASP, "https://cwe.mitre.org/data/definitions/602.html"],
  },
  "AUTH-006": {
    title: "Stripe webhook trusts the request body without verifying the signature",
    severity: "critical",
    cwe: "CWE-345",
    explanation:
      "This endpoint acts on Stripe event types after merely parsing the request body. Anyone can POST a fake checkout.session.completed event and get a free upgrade, credits or an order marked as paid.",
    summary: "Read the raw body and verify it with stripe.webhooks.constructEvent before acting on it.",
    snippet: `const raw = await req.text();
const event = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);`,
    instruction:
      "this Stripe webhook parses the body and acts on event.type without signature verification. Read the raw body (req.text()) and call stripe.webhooks.constructEvent with the stripe-signature header and STRIPE_WEBHOOK_SECRET; return 400 on failure.",
    refs: ["https://docs.stripe.com/webhooks#verify-events"],
  },
  "AUTH-007": {
    title: "Supabase service_role key used in client-side code",
    severity: "critical",
    cwe: "CWE-798",
    explanation:
      "The service_role key bypasses all Row Level Security. Code that ships to the browser exposes it (or tries to), so any visitor can read, modify and delete every row in your database.",
    summary: "Use the anon key in client code; keep service_role in server-only modules and rotate the exposed key.",
    snippet: `// client
createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
// server only (route handler / server action)
createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);`,
    instruction:
      "the Supabase service_role key is referenced from client-side code. Switch this client to the anon key, move privileged operations into a server-only route handler, never prefix the key with NEXT_PUBLIC_/VITE_, and rotate the key in the Supabase dashboard.",
    refs: ["https://supabase.com/docs/guides/api/api-keys", "https://cwe.mitre.org/data/definitions/798.html"],
  },
};
