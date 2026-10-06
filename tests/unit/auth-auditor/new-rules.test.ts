import { describe, expect, it } from "vitest";
import { ruleIdsFor, scan } from "./helpers.js";

const src = (...lines: string[]): string => lines.join("\n") + "\n";
const only = async (files: Record<string, string>, rule: string) => (await scan(files)).filter((f) => f.ruleId === rule);

describe("AUTH-008 getSession() for server authorization", () => {
  const bad = src(
    'import { createClient } from "@/lib/supabase/server";',
    "export async function GET() {",
    "  const supabase = createClient();",
    "  const { data: { session } } = await supabase.auth.getSession();",
    '  if (!session) return new Response(null, { status: 401 });',
    '  const { data } = await supabase.from("notes").select("*").eq("user_id", session.user.id);',
    "  return Response.json(data);",
    "}",
  );
  it("flags getSession used for authorization in a route handler", async () => {
    const f = await only({ "app/api/notes/route.ts": bad }, "AUTH-008");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.evidence[0]?.line).toBe(4);
  });
  it("FP guard: getUser() in the same unit is fine", async () => {
    const ok = bad.replace("supabase.auth.getSession()", "supabase.auth.getUser()").replace("{ session }", "{ user: session }");
    expect(await only({ "app/api/notes/route.ts": ok }, "AUTH-008")).toEqual([]);
    const both = bad.replace("  if (!session)", "  await supabase.auth.getUser();\n  if (!session)");
    expect(await only({ "app/api/notes/route.ts": both }, "AUTH-008")).toEqual([]);
  });
  it("FP guard: getSession in a client component is fine", async () => {
    const client = src('"use client";', "export function A() {", "  supabase.auth.getSession().then(({ data }) => setS(data.session));", "  return null;", "}");
    expect(await only({ "components/A.tsx": client }, "AUTH-008")).toEqual([]);
  });
});

describe("AUTH-009 user_metadata for authorization", () => {
  it("flags user_metadata.role in a condition as critical", async () => {
    const code = src(
      "export async function GET() {",
      "  const { data: { user } } = await supabase.auth.getUser();",
      '  if (user?.user_metadata?.role !== "admin") return new Response(null, { status: 403 });',
      "  return Response.json({ secret: 1 });",
      "}",
    );
    const f = await only({ "app/api/admin/stats/route.ts": code }, "AUTH-009");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("critical");
  });
  it("flags a destructured is_admin later used as a gate", async () => {
    const code = src("export async function GET(user: any) {", "  const { is_admin } = user.user_metadata;", "  if (is_admin) { return 1; }", "}");
    expect(await only({ "lib/a.ts": code }, "AUTH-009")).toHaveLength(1);
  });
  it("control: app_metadata.role is safe", async () => {
    const code = src('export const isAdmin = (user: any) => user.app_metadata?.role === "admin";');
    expect(await only({ "lib/a.ts": code }, "AUTH-009")).toEqual([]);
  });
  it("FP guard: user_metadata display name is not authorization", async () => {
    const code = src("export const name = (user: any) => user.user_metadata.full_name;");
    expect(await only({ "lib/a.ts": code }, "AUTH-009")).toEqual([]);
  });
});

describe("AUTH-010 mass assignment", () => {
  const route = (write: string, pre = "  const body = await req.json();") =>
    src("export async function PATCH(req: Request) {", "  const user = await getCurrentUser();", pre, `  ${write}`, "  return Response.json({});", "}");
  it.each([
    ["prisma data: body", "await prisma.user.update({ where: { id: user.id }, data: body });"],
    ["prisma data spread", "await prisma.user.update({ where: { id: user.id }, data: { ...body } });"],
    ["drizzle .set(body)", "await db.update(users).set(body).where(eq(users.id, user.id));"],
    ["drizzle .values(body)", "await db.insert(users).values(body);"],
    ["mongoose create", "await User.create(body);"],
    ["mongoose findByIdAndUpdate", "await User.findByIdAndUpdate(user.id, body);"],
    ["supabase insert", 'await supabase.from("profiles").insert(body);'],
    ["supabase update", 'await supabase.from("profiles").update(body).eq("id", user.id);'],
    ["supabase upsert array", 'await supabase.from("profiles").upsert([body]);'],
    ["Object.assign + save", "Object.assign(entity, body); await entity.save();"],
  ])("flags %s", async (_n, write) => {
    const f = await only({ "app/api/me/route.ts": route(write) }, "AUTH-010");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });
  it("flags body obtained by awaiting req.json() inline", async () => {
    const code = route("await prisma.user.create({ data: await req.json() });", "");
    expect(await only({ "app/api/me/route.ts": code }, "AUTH-010")).toHaveLength(1);
  });
  it("FP guard: zod-parsed result, explicit picks and pick() helpers are fine", async () => {
    const zod = route("await prisma.user.update({ where: { id: user.id }, data: input });", "  const input = schema.parse(await req.json());");
    expect(await only({ "app/api/me/route.ts": zod }, "AUTH-010")).toEqual([]);
    const picks = route("await prisma.user.update({ where: { id: user.id }, data: { name: body.name, bio: body.bio } });");
    expect(await only({ "app/api/me/route.ts": picks }, "AUTH-010")).toEqual([]);
    const pick = route("await db.update(users).set(pick(body, ['name']));");
    expect(await only({ "app/api/me/route.ts": pick }, "AUTH-010")).toEqual([]);
    const safe = route("await supabase.from('profiles').update(safeParse.data).eq('id', user.id);", "  const safeParse = schema.safeParse(await req.json());");
    expect(await only({ "app/api/me/route.ts": safe }, "AUTH-010")).toEqual([]);
  });
  it("FP guard: not request data", async () => {
    const code = src("export async function POST() {", "  const row = { name: 'x' };", "  await prisma.user.create({ data: row });", "  return Response.json({});", "}");
    expect(await only({ "app/api/me/route.ts": code }, "AUTH-010")).toEqual([]);
  });
  it("escalates wording when the target model has privilege columns", async () => {
    const files = {
      "prisma/schema.prisma": "model User {\n  id String @id\n  role String\n  credits Int\n}\n",
      "app/api/me/route.ts": route("await prisma.user.update({ where: { id: user.id }, data: body });"),
    };
    const f = await only(files, "AUTH-010");
    expect(f[0]?.title).toMatch(/privilege/i);
    expect(f[0]?.explanation).toMatch(/role\/admin\/credit/);
  });
  it("uses the plain wording when no privileged columns are visible", async () => {
    const files = {
      "prisma/schema.prisma": "model User {\n  id String @id\n  name String\n}\n",
      "app/api/me/route.ts": route("await prisma.user.update({ where: { id: user.id }, data: body });"),
    };
    expect((await only(files, "AUTH-010"))[0]?.title).not.toMatch(/privilege/i);
  });
});

describe("AUTH-011 payment tampering", () => {
  const checkout = (amount: string, pre = "  const body = await req.json();") =>
    src(
      "export async function POST(req: Request) {",
      "  const user = await getCurrentUser();",
      pre,
      "  const s = await stripe.checkout.sessions.create({",
      '    mode: "payment",',
      `    line_items: [{ price_data: { currency: "usd", product_data: { name: "x" }, unit_amount: ${amount} }, quantity: 1 }],`,
      "  });",
      "  return Response.json({ url: s.url });",
      "}",
    );
  it("flags unit_amount taken from the request as critical", async () => {
    const f = await only({ "app/api/checkout/route.ts": checkout("body.amount") }, "AUTH-011");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("critical");
  });
  it("flags Number(body.price) * 100", async () => {
    expect(await only({ "app/api/checkout/route.ts": checkout("Number(body.price) * 100") }, "AUTH-011")).toHaveLength(1);
  });
  it("control: price looked up on the server is fine", async () => {
    const code = checkout("product.price", "  const { productId } = await req.json();\n  const product = await db.product.findUnique({ where: { id: productId } });");
    expect(await only({ "app/api/checkout/route.ts": code }, "AUTH-011")).toEqual([]);
  });
  it("FP guard: a client-chosen Stripe price id is not an amount", async () => {
    const code = src(
      "export async function POST(req: Request) {",
      "  const { priceId } = await req.json();",
      "  const s = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: priceId, quantity: 1 }] });",
      "  return Response.json({ url: s.url });",
      "}",
    );
    expect(await only({ "app/api/checkout/route.ts": code }, "AUTH-011")).toEqual([]);
  });
  const success = (verify: string) =>
    src(
      "export default async function Success({ searchParams }: { searchParams: { session_id: string } }) {",
      "  const user = await getCurrentUser();",
      verify,
      '  await supabase.from("profiles").update({ is_premium: true }).eq("id", user.id);',
      "  return null;",
      "}",
    );
  it("flags a success page that grants premium from session_id without retrieving the session", async () => {
    const f = await only({ "app/success/page.tsx": success("  const id = searchParams.session_id;") }, "AUTH-011");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });
  it("control: retrieving the checkout session first is fine", async () => {
    const ok = success("  const s = await stripe.checkout.sessions.retrieve(searchParams.session_id);\n  if (s.payment_status !== 'paid') return null;");
    expect(await only({ "app/success/page.tsx": ok }, "AUTH-011")).toEqual([]);
  });
});

describe("AUTH-012 weak randomness for secrets", () => {
  it.each([
    ["const resetToken = Math.random().toString(36).slice(2);"],
    ["const otp = Math.floor(100000 + Math.random() * 900000);"],
    ["const apiKey = 'k_' + Date.now();"],
    ["const user = { id: 1, inviteCode: Math.random().toString(36) };"],
    ["export function generateToken() { return Math.random().toString(36); }"],
  ])("flags %s in server code", async (line) => {
    const code = src(line, "export const x = 1;");
    expect(await only({ "lib/auth.ts": code }, "AUTH-012")).toHaveLength(1);
  });
  it("FP guard: non-secret names and client UI never fire", async () => {
    expect(await only({ "lib/ui.ts": "const jitter = Math.random(); const colorCode = 'red'; const startedAt = Date.now();\n" }, "AUTH-012")).toEqual([]);
    expect(await only({ "components/Card.tsx": '"use client";\nexport const c = () => { const resetToken = Math.random(); return resetToken; };\n' }, "AUTH-012")).toEqual([]);
  });
  it("FP guard: token expiry timestamps from Date.now are not secrets", async () => {
    expect(await only({ "lib/t.ts": "export const tokenExpiresAt = Date.now() + 3600_000;\nexport const sessionStart = Date.now();\n" }, "AUTH-012")).toEqual([]);
  });
  it("control: crypto randomness is clean", async () => {
    expect(await only({ "lib/t.ts": 'import { randomBytes } from "node:crypto";\nexport const resetToken = randomBytes(32).toString("hex");\n' }, "AUTH-012")).toEqual([]);
  });
});

describe("AUTH-013 weak password handling", () => {
  it.each(["md5", "sha1", "sha256"])("flags createHash(%s) over a password", async (algo) => {
    const code = src('import { createHash } from "crypto";', `export const h = (password: string) => createHash("${algo}").update(password).digest("hex");`);
    const f = await only({ "lib/pw.ts": code }, "AUTH-013");
    expect(f).toHaveLength(1);
    expect(f[0]?.title).toMatch(/fast/i);
  });
  it("control: createHash over a non-password (etag) is fine", async () => {
    const code = src('import { createHash } from "crypto";', 'export const etag = (body: string) => createHash("sha1").update(body).digest("hex");');
    expect(await only({ "lib/etag.ts": code }, "AUTH-013")).toEqual([]);
  });
  it("flags bcrypt rounds below 10 (literal, genSalt and const)", async () => {
    for (const body of ["bcrypt.hash(pw, 8)", "bcrypt.hashSync(pw, 4)", "bcrypt.genSaltSync(6)"]) {
      const code = src('import bcrypt from "bcryptjs";', `export const h = (pw: string) => ${body};`);
      expect(await only({ "lib/pw.ts": code }, "AUTH-013"), body).toHaveLength(1);
    }
    const viaConst = src('import bcrypt from "bcrypt";', "const ROUNDS = 5;", "export const h = (pw: string) => bcrypt.hash(pw, ROUNDS);");
    expect(await only({ "lib/pw.ts": viaConst }, "AUTH-013")).toHaveLength(1);
  });
  it("control: bcrypt cost 12 and 10 are fine", async () => {
    for (const n of [10, 12]) {
      const code = src('import bcrypt from "bcryptjs";', `export const h = (pw: string) => bcrypt.hash(pw, ${n});`);
      expect(await only({ "lib/pw.ts": code }, "AUTH-013")).toEqual([]);
    }
  });
  it("flags plaintext comparison and plaintext storage", async () => {
    const login = src(
      "export async function POST(req: Request) {",
      "  const { email, password } = await req.json();",
      "  const user = await prisma.user.findUnique({ where: { email } });",
      "  if (user.password === password) return Response.json({ ok: true });",
      "  return new Response(null, { status: 401 });",
      "}",
    );
    expect(await only({ "app/api/login/route.ts": login }, "AUTH-013")).toHaveLength(1);
    const register = src(
      "export async function POST(req: Request) {",
      "  const body = await req.json();",
      "  await prisma.user.create({ data: { email: body.email, password: body.password } });",
      "  return Response.json({});",
      "}",
    );
    expect(await only({ "app/api/register/route.ts": register }, "AUTH-013")).toHaveLength(1);
  });
  it("control: hashed storage and bcrypt.compare are fine", async () => {
    const code = src(
      'import bcrypt from "bcryptjs";',
      "export async function POST(req: Request) {",
      "  const body = await req.json();",
      "  const password = await bcrypt.hash(body.password, 12);",
      "  await prisma.user.create({ data: { email: body.email, password } });",
      "  return Response.json({});",
      "}",
    );
    expect(await only({ "app/api/register/route.ts": code }, "AUTH-013")).toEqual([]);
  });
  it("FP guard: provider sign-up (Supabase) passes the password to a service that hashes it", async () => {
    const code = src(
      "export async function POST(req: Request) {",
      "  const { email, password } = await req.json();",
      "  await supabase.auth.signUp({ email, password });",
      "  return Response.json({});",
      "}",
    );
    expect(await only({ "app/api/register/route.ts": code }, "AUTH-013")).toEqual([]);
  });
});

describe("AUTH-014 auth endpoints without rate limiting", () => {
  const login = src("export async function POST(req: Request) {", "  const { email, password } = await req.json();", "  const user = await verifyCredentials(email, password);", "  return Response.json({ ok: !!user });", "}");
  it("flags a login route handler with medium severity", async () => {
    const f = await only({ "app/api/auth/login/route.ts": login }, "AUTH-014");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.confidence).toBe("medium");
  });
  it("flags a server action named signIn / forgotPassword", async () => {
    const code = src('"use server";', "export async function forgotPassword(email: string) { await sendReset(email); }");
    expect(await only({ "app/actions.ts": code }, "AUTH-014")).toHaveLength(1);
  });
  it("lowers confidence when a hosted auth provider is called", async () => {
    const code = src("export async function POST(req: Request) {", "  const { email, password } = await req.json();", "  await supabase.auth.signInWithPassword({ email, password });", "  return Response.json({});", "}");
    const [f] = await only({ "app/api/login/route.ts": code }, "AUTH-014");
    expect(f?.confidence).toBe("low");
    expect(f?.severity).toBe("low");
  });
  it("control: an own credential check stays medium even when an auth provider is installed", async () => {
    const files = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }), "app/api/auth/login/route.ts": login };
    expect((await only(files, "AUTH-014"))[0]?.severity).toBe("medium");
  });
  it("control: a rate limiter in the unit, the file or the middleware silences it", async () => {
    const limited = src('import { Ratelimit } from "@upstash/ratelimit";', "const limiter = new Ratelimit({});", login);
    expect(await only({ "app/api/auth/login/route.ts": limited }, "AUTH-014")).toEqual([]);
    const mw = 'import { Ratelimit } from "@upstash/ratelimit";\nexport function middleware() {}\n';
    expect(await only({ "middleware.ts": mw, "app/api/auth/login/route.ts": login }, "AUTH-014")).toEqual([]);
  });
  it("FP guard: non-auth routes and GET handlers are not flagged", async () => {
    expect(await only({ "app/api/items/route.ts": login }, "AUTH-014")).toEqual([]);
    expect(await only({ "app/api/auth/login/route.ts": login.replace("POST", "GET") }, "AUTH-014")).toEqual([]);
  });
});

describe("AUTH-015 debug / seed / cron / admin routes without auth", () => {
  const seed = src("export async function GET() {", '  await prisma.user.createMany({ data: [{ name: "a" }] });', '  return Response.json({ ok: true });', "}");
  it("flags an unauthenticated seed route as high", async () => {
    const f = await scan({ "app/api/seed/route.ts": seed });
    expect(f.map((x) => [x.ruleId, x.severity])).toEqual([["AUTH-015", "high"]]);
  });
  it("is critical when it deletes, migrates, execs or dumps process.env", async () => {
    const wipe = src("export async function POST() {", "  await prisma.user.deleteMany();", "  return Response.json({});", "}");
    expect((await only({ "app/api/reset-db/route.ts": wipe }, "AUTH-015"))[0]?.severity).toBe("critical");
    const env = src("export async function GET() { return Response.json(process.env); }");
    expect((await only({ "app/api/debug/route.ts": env }, "AUTH-015"))[0]?.severity).toBe("critical");
  });
  it("supersedes AUTH-002 for the same handler", async () => {
    expect(await ruleIdsFor({ "app/api/admin/users/route.ts": src("export async function GET() { return Response.json(await prisma.user.findMany()); }") })).toEqual(["AUTH-015"]);
  });
  it("control: auth, CRON_SECRET, shared secret header or production guard silence it", async () => {
    const auth = seed.replace("  await prisma", "  const user = await getCurrentUser();\n  if (!user) return new Response(null, { status: 401 });\n  await prisma");
    const cron = seed.replace("  await prisma", '  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });\n  await prisma').replace("GET()", "GET(req: Request)");
    const secret = seed.replace("  await prisma", '  if (req.headers.get("x-seed-secret") !== process.env.SEED) return new Response(null, { status: 401 });\n  await prisma').replace("GET()", "GET(req: Request)");
    const prod = seed.replace("  await prisma", '  if (process.env.NODE_ENV === "production") return new Response(null, { status: 404 });\n  await prisma');
    for (const [name, code] of Object.entries({ auth, cron, secret, prod })) {
      expect(await only({ "app/api/seed/route.ts": code }, "AUTH-015"), name).toEqual([]);
    }
  });
  it("FP guard: ordinary routes, trivial handlers and test directories are ignored", async () => {
    expect(await only({ "app/api/items/route.ts": seed }, "AUTH-015")).toEqual([]);
    expect(await only({ "app/api/test/route.ts": "export async function GET() { return Response.json({ ok: true }); }\n" }, "AUTH-015")).toEqual([]);
    expect(await only({ "__tests__/api/seed/route.ts": seed }, "AUTH-015")).toEqual([]);
  });
  it("scans route files whose URL segment is literally test", async () => {
    expect(await only({ "app/api/test/route.ts": seed }, "AUTH-015")).toHaveLength(1);
  });
});

describe("AUTH-016 inverted auth check", () => {
  const handler = (check: string) =>
    src("export async function GET() {", "  const { data: { user } } = await supabase.auth.getUser();", check, "  return Response.json({ secret: 1 });", "}");
  it.each([
    ['  if (user) return Response.json({ error: "Unauthorized" }, { status: 401 });'],
    ["  if (user) { return new Response(null, { status: 403 }); }"],
  ])("flags %s", async (check) => {
    expect(await only({ "app/api/x/route.ts": handler(check) }, "AUTH-016")).toHaveLength(1);
  });
  it("flags if (session) { return ...401 }", async () => {
    const code = src("export async function GET() {", "  const session = await auth();", "  if (session) {", '    return new Response("Unauthorized", { status: 401 });', "  }", "  return Response.json({});", "}");
    expect(await only({ "app/api/x/route.ts": code }, "AUTH-016")).toHaveLength(1);
  });
  it("control: the correct negated check is clean", async () => {
    expect(await only({ "app/api/x/route.ts": handler('  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });') }, "AUTH-016")).toEqual([]);
  });
  it("FP guard: if (user) with a normal branch, or an 'already signed in' message", async () => {
    expect(await only({ "app/api/x/route.ts": handler("  if (user) { await track(user.id); }") }, "AUTH-016")).toEqual([]);
    expect(await only({ "app/api/x/route.ts": handler('  if (user) return new Response("Already signed in", { status: 403 });') }, "AUTH-016")).toEqual([]);
  });
});

describe("AUTH-017 insecure cookies, token expiry and token storage", () => {
  const cookieFile = (call: string) => src('import { cookies } from "next/headers";', "export async function POST() {", `  ${call}`, "  return Response.json({});", "}");
  it.each([
    ['cookies().set("session", token);'],
    ['cookies().set("token", t, { path: "/" });'],
    ['cookies().set("auth", t, { httpOnly: false });'],
    ['cookies().set("jwt", t, { httpOnly: true, secure: false });'],
  ])("flags %s", async (call) => {
    const f = await only({ "app/api/login/route.ts": cookieFile(call) }, "AUTH-017");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });
  it("flags res.cookie without httpOnly", async () => {
    const code = src('import express from "express";', "const app = express();", 'app.post("/x", (req, res) => { res.cookie("sid", "v"); res.end(); });');
    expect(await only({ "server/a.ts": code }, "AUTH-017")).toHaveLength(1);
  });
  it("control: httpOnly cookies, non-auth cookies, deletions and spread options are fine", async () => {
    for (const call of [
      'cookies().set("session", t, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" });',
      'cookies().set("theme", "dark");',
      'cookies().set("session", "", { maxAge: 0 });',
      'cookies().set("session", t, opts);',
      'cookies().set(name, value, options);',
    ]) {
      expect(await only({ "app/api/login/route.ts": cookieFile(call) }, "AUTH-017"), call).toEqual([]);
    }
  });
  it("flags jwt.sign without expiresIn but not with it", async () => {
    const bad = src('import jwt from "jsonwebtoken";', "export const t = (u: string) => jwt.sign({ sub: u }, process.env.S!);");
    const f = await only({ "lib/j.ts": bad }, "AUTH-017");
    expect(f).toHaveLength(1);
    expect(f[0]?.title).toMatch(/expiry/i);
    const ok = bad.replace("process.env.S!)", 'process.env.S!, { expiresIn: "1h" })');
    expect(await only({ "lib/j.ts": ok }, "AUTH-017")).toEqual([]);
    const exp = bad.replace("{ sub: u }", "{ sub: u, exp: 1 }");
    expect(await only({ "lib/j.ts": exp }, "AUTH-017")).toEqual([]);
  });
  it("flags tokens in web storage (refresh token is high)", async () => {
    const client = src('"use client";', 'export function save(t: string, r: string) { localStorage.setItem("accessToken", t); sessionStorage.setItem("refresh_token", r); localStorage.setItem("theme", "d"); }');
    const f = await only({ "components/auth.tsx": client }, "AUTH-017");
    expect(f.map((x) => x.severity).sort()).toEqual(["high", "medium"]);
  });
});

describe("AUTH-018 dangerous OAuth account linking", () => {
  it("flags allowDangerousEmailAccountLinking: true as high", async () => {
    const code = src('import GitHub from "next-auth/providers/github";', "export default { providers: [GitHub({ allowDangerousEmailAccountLinking: true })] };");
    const f = await only({ "auth.ts": code }, "AUTH-018");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });
  it("control: false or absent is fine; comments do not count", async () => {
    expect(await only({ "auth.ts": "export default { p: [GitHub({ allowDangerousEmailAccountLinking: false })] };\n" }, "AUTH-018")).toEqual([]);
    expect(await only({ "auth.ts": "// allowDangerousEmailAccountLinking: true\nexport default {};\n" }, "AUTH-018")).toEqual([]);
  });
});

describe("AUTH-019 host-header poisoning in reset/invite links", () => {
  it("flags redirectTo built from headers().get('origin')", async () => {
    const code = src(
      'import { headers } from "next/headers";',
      "export async function forgot(email: string) {",
      '  const origin = headers().get("origin");',
      "  await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${origin}/reset` });",
      "}",
    );
    expect(await only({ "app/actions.ts": '"use server";\n' + code }, "AUTH-019")).toHaveLength(1);
  });
  it("flags req.headers.host in a mail link", async () => {
    const code = src("export async function POST(req: any, res: any) {", "  const link = `https://${req.headers.host}/reset?t=${token}`;", "  await transporter.sendMail({ to: email, html: link });", "}");
    expect(await only({ "pages/api/forgot.ts": code }, "AUTH-019")).toHaveLength(1);
  });
  it("control: a fixed site URL from config is fine", async () => {
    const code = src("export async function forgot(email: string) {", "  await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${process.env.NEXT_PUBLIC_SITE_URL}/reset` });", "}");
    expect(await only({ "app/actions.ts": '"use server";\n' + code }, "AUTH-019")).toEqual([]);
  });
});

describe("new rule findings carry full remediation data", () => {
  it("includes explanation, patch, agentPrompt with file+line, references and cwe", async () => {
    const code = src("export async function PATCH(req: Request) {", "  const body = await req.json();", "  await prisma.user.update({ where: { id: 1 }, data: body });", "}");
    const f = (await only({ "app/api/me/route.ts": code }, "AUTH-010"))[0];
    expect(f?.cwe).toBe("CWE-915");
    expect(f?.explanation.length).toBeGreaterThan(40);
    expect(f?.fix.patch?.diff).toBeTruthy();
    expect(f?.fix.agentPrompt).toContain("app/api/me/route.ts at line 3");
    expect(f?.fix.references.length).toBeGreaterThan(0);
  });
});
