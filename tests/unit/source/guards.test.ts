import { describe, expect, it } from "vitest";
import { GUARDS, guardMatches, unitHas } from "../../../src/core/source/guards.js";
import type { GuardName } from "../../../src/core/source/guards.js";
import { findUnits, handlerUnits } from "../../../src/core/source/units.js";
import { EXPRESS_APP, EXPRESS_PATH, NEXT_ROUTE, NEXT_ROUTE_PATH, src } from "./fixtures.js";

/** Wraps a body in a route handler and asks whether the unit has the guard. */
function has(guard: GuardName, body: string, extra = ""): boolean {
  const s = src("app/api/x/route.ts", `${extra}\nexport async function POST(request) {\n${body}\n}\n`);
  const unit = findUnits(s).find((u) => u.name === "POST")!;
  return unitHas(s, unit, guard);
}

describe("auth guard", () => {
  const positive: Array<[string, string]> = [
    ["supabase getUser", "const { data: { user } } = await supabase.auth.getUser();"],
    ["supabase getClaims", "const { data } = await supabase.auth.getClaims();"],
    ["getServerSession", "const session = await getServerSession(authOptions);"],
    ["auth()", "const { userId } = await auth();"],
    ["clerk auth.protect", "await auth.protect();"],
    ["currentUser", "const user = await currentUser();"],
    ["jwtVerify", "const { payload } = await jwtVerify(token, key);"],
    ["jwt.verify", "const p = jwt.verify(token, secret);"],
    ["next-auth getToken", "const token = await getToken({ req: request });"],
    ["firebase verifyIdToken", "const d = await admin.auth().verifyIdToken(t);"],
    ["lucia validateRequest", "const { user } = await validateRequest();"],
    ["requireUser helper", "const user = await requireUser();"],
    ["getCurrentUser helper", "const user = await getCurrentUser();"],
    ["getServerProfile helper", "const p = await getServerProfile();"],
    ["verifyAdmin helper", "await verifyAdmin(request);"],
    ["assertLoggedIn helper", "assertLoggedIn(session);"],
    ["inbound authorization header", "const h = request.headers.get('authorization');"],
    ["inbound Authorization (case)", "const h = req.headers.get('Authorization');"],
    ["headers.authorization", "const h = req.headers.authorization;"],
    ["req.header()", "const h = req.header('authorization');"],
    ["CRON_SECRET", "if (h !== `Bearer ${process.env.CRON_SECRET}`) return new Response('no', { status: 401 });"],
    ["bearer secret compare", "if (authHeader !== `Bearer ${process.env.API_SECRET}`) return;"],
    ["req.user", "if (!req.user) return;"],
    ["wrapper callback param", "return withAuth(async (req, user) => { return ok(user); });"],
    ["wrapper callback destructured", "return withAuth(async (req, { user }) => { return ok(user); });"],
    ["passport authenticate", "passport.authenticate('jwt', { session: false });"],
    ["better-auth", "const s = await auth.api.getSession({ headers: await headers() });"],
  ];
  it.each(positive)("counts: %s", (_n, body) => expect(has("auth", body)).toBe(true));

  const negative: Array<[string, string]> = [
    ["outgoing Authorization header to a third party", "await fetch('https://api.vendor.com/x', { headers: { Authorization: `Bearer ${process.env.VENDOR_KEY}` } });"],
    ["outgoing 'authorization' quoted key", "await fetch(u, { headers: { 'Authorization': 'Bearer ' + k } });"],
    ["getServerSideProps", "const p = getServerSideProps(ctx);"],
    ["checkUserExists", "const exists = await checkUserExists(email);"],
    ["getUserById", "const u = await getUserById(id);"],
    ["auth in a string", "const a = 'await auth()';"],
    ["auth in a comment", "// await getServerSession()\nconst a = 1;"],
    ["auth in a regex", "const r = /getUser\\(/;"],
    ["single-param map callback named user", "const names = users.map((user) => user.name);"],
    ["author helper", "const a = getAuthor(id);"],
    ["plain db call", "await db.insert(x);"],
  ];
  it.each(negative)("does not count: %s", (_n, body) => expect(has("auth", body)).toBe(false));

  it("counts matches that start inside ${}", () => {
    expect(has("auth", "const s = `user: ${(await getServerSession()).user.id}`;")).toBe(true);
  });
});

describe("rate limit guard", () => {
  it.each([
    "const { success } = await ratelimit.limit(ip);",
    "const limiter = new RateLimiterMemory({});",
    "await rateLimit(request);",
    "const r = checkRateLimit(request);",
    "await throttle(request);",
  ])("counts %s", (body) => expect(has("rateLimit", body)).toBe(true));
  it.each(["// TODO add rate limit", "const s = 'rate limited';", "const x = 1;", "const unlimited = 3;"])("does not count %s", (body) =>
    expect(has("rateLimit", body)).toBe(false),
  );
});

describe("ownership guard", () => {
  const positive: Array<[string, string]> = [
    ["supabase .eq user_id", "await supabase.from('t').select().eq('id', id).eq('user_id', user.id);"],
    ["supabase .eq id user.id", "await supabase.from('profiles').select().eq('id', user.id);"],
    ["session.user.id", "await supabase.from('t').delete().eq('owner_id', session.user.id);"],
    ["prisma where userId", "await db.post.findFirst({ where: { id, userId: session.user.id } });"],
    ["ownerId currentUser.id", "await db.doc.update({ where: { id }, data: { ownerId: currentUser.id } });"],
    ["colon form from auth() var", "const { userId } = await auth();\nawait db.todo.findMany({ where: { userId: userId } });"],
    ["shorthand from auth var", "const userId = session.user.id;\nawait db.todo.findMany({ where: { userId } });"],
    ["eq with auth var", "const uid = (await supabase.auth.getUser()).data.user.id;\nawait supabase.from('t').select().eq('user_id', uid);"],
    ["post-fetch !== user.id", "const doc = await db.doc.find(id);\nif (doc.ownerId !== user.id) return forbidden();"],
    ["post-fetch === session.user.id", "if (session.user.id === doc.userId) ok();"],
    ["verify access helper", "await verifyCurrentUserHasAccessToPost(id);"],
    ["canEdit helper", "if (!canEdit(user, doc)) return;"],
    ["isOwner helper", "if (!isOwner(doc, user)) return;"],
  ];
  it.each(positive)("counts: %s", (_n, body) => expect(has("ownership", body)).toBe(true));

  const negative: Array<[string, string]> = [
    ["request-supplied id only", "const { id } = await request.json();\nawait db.post.delete({ where: { id } });"],
    ["colon form from request body", "const { userId } = await request.json();\nawait db.todo.findMany({ where: { userId: userId } });"],
    ["shorthand from request body", "const userId = request.nextUrl.searchParams.get('u');\nawait db.todo.findMany({ where: { userId } });"],
    ["eq with request value", "await supabase.from('t').select().eq('user_id', body.userId);"],
    ["unrelated eq", "await supabase.from('t').select().eq('id', id);"],
    ["ownership in a comment", "// .eq('user_id', user.id)\nawait db.x.find();"],
    ["checkUserExists", "await checkUserExists(id);"],
  ];
  it.each(negative)("does not count: %s", (_n, body) => expect(has("ownership", body)).toBe(false));
});

describe("signature guard", () => {
  it.each([
    "const e = stripe.webhooks.constructEvent(body, sig, secret);",
    "const e = await stripe.webhooks.constructEventAsync(body, sig, secret);",
    "const h = crypto.createHmac('sha256', secret).update(body).digest('hex');",
    "if (!crypto.timingSafeEqual(a, b)) return;",
    "const wh = new Webhook(secret); wh.verify(body, headers);",
    "if (!verifySignature(body, sig)) return;",
    "await verifyWebhook(request);",
    "await octokit.webhooks.verify(body, sig);",
  ])("counts %s", (body) => expect(has("signature", body)).toBe(true));
  it.each(["const sig = request.headers.get('stripe-signature');", "// constructEvent", "const a = 'createHmac';"])("does not count %s", (body) =>
    expect(has("signature", body)).toBe(false),
  );
});

describe("validation guard", () => {
  it.each([
    "const b = schema.parse(await request.json());",
    "const b = Body.safeParse(x);",
    "const b = z.object({ a: z.string() }).parse(x);",
    "const b = await userSchema.parseAsync(x);",
    "const b = yup.object().validateSync(x);",
    "const b = v.parse(Schema, x);",
    "app.use(zValidator('json', schema));",
    "const errors = validationResult(req);",
    "await validateBody(request);",
  ])("counts %s", (body) => expect(has("validation", body)).toBe(true));
  it.each([
    "const j = JSON.parse(text);",
    "const d = Date.parse(s);",
    "const u = url.parse(s);",
    "const p = path.parse(s);",
    "const q = qs.parse(s);",
    "const n = Number.parseInt(s);",
    "// schema.parse(x)",
    "const s = 'schema.parse(x)';",
  ])("does not count %s", (body) => expect(has("validation", body)).toBe(false));
});

describe("unit scoping", () => {
  it("guards are evaluated per unit, not per file", () => {
    const s = src(
      "app/api/x/route.ts",
      "export async function GET() {\n  const { data: { user } } = await supabase.auth.getUser();\n  return Response.json(user);\n}\nexport async function POST(request) {\n  await db.insert(await request.json());\n}\n",
    );
    const [get, post] = handlerUnits(s);
    expect(unitHas(s, get!, "auth")).toBe(true);
    expect(unitHas(s, post!, "auth")).toBe(false);
  });

  it("Next fixture: only GET is authenticated and owner-scoped", () => {
    const s = src(NEXT_ROUTE_PATH, NEXT_ROUTE);
    const by = (m: string) => handlerUnits(s).find((h) => h.httpMethod === m)!;
    expect(unitHas(s, by("GET"), "auth")).toBe(true);
    expect(unitHas(s, by("GET"), "ownership")).toBe(true);
    expect(unitHas(s, by("DELETE"), "auth")).toBe(false);
    expect(unitHas(s, by("POST"), "validation")).toBe(true);
    expect(unitHas(s, by("DELETE"), "validation")).toBe(false);
  });

  it("Express middleware args count for the route and extra ranges are scanned", () => {
    const s = src(EXPRESS_PATH, EXPRESS_APP);
    const [get, post] = handlerUnits(s);
    expect(unitHas(s, post!, "rateLimit")).toBe(true);
    expect(unitHas(s, get!, "rateLimit")).toBe(false);
    const t = src("app.js", "const app = express();\nfunction list(req, res) { res.json(1); }\napp.get('/l', requireAuth, list);\n");
    expect(unitHas(t, handlerUnits(t)[0]!, "auth")).toBe(true);
  });

  it("router-level app.use(auth) counts only when asked", () => {
    const s = src("app.js", "const app = express();\napp.use(requireAuth);\napp.get('/a', (req, res) => res.json(1));\n");
    const h = handlerUnits(s).find((u) => u.httpMethod === "GET")!;
    expect(unitHas(s, h, "auth")).toBe(false);
    expect(unitHas(s, h, "auth", { includeRouterMiddleware: true })).toBe(true);
    const other = src("app.js", "const app = express();\nconst r = express.Router();\nr.use(requireAuth);\napp.get('/a', (req, res) => res.json(1));\n");
    expect(unitHas(other, handlerUnits(other).find((u) => u.httpMethod === "GET")!, "auth", { includeRouterMiddleware: true })).toBe(false);
  });

  it("guardMatches returns offsets usable for line lookup", () => {
    const s = src("app/api/x/route.ts", "export async function POST() {\n  await getServerSession();\n}\n");
    const unit = findUnits(s)[0]!;
    const m = guardMatches(s, unit, "auth");
    expect(m).toHaveLength(1);
    expect(s.raw.slice(m[0]!.index, m[0]!.index + 16)).toBe("getServerSession");
  });

  it("exposes the shared catalog", () => {
    for (const name of ["auth", "rateLimit", "ownership", "signature", "validation"] as const) {
      expect(GUARDS[name].re).toBeInstanceOf(RegExp);
      expect(["bare", "code"]).toContain(GUARDS[name].view);
    }
  });
});
