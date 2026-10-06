import { describe, expect, it } from "vitest";
import { ruleIdsFor, scan } from "./helpers.js";

const src = (...lines: string[]): string => lines.join("\n") + "\n";

describe("corpus regressions: helpers in the same file", () => {
  const route = (helperBody: string, call = "await verifyCurrentUserHasAccessToPost(params.postId)") =>
    src(
      'import { getServerSession } from "next-auth"',
      "export async function DELETE(req: Request, context: { params: { postId: string } }) {",
      "  const { params } = context",
      `  if (!(${call})) return new Response(null, { status: 403 })`,
      "  await db.post.delete({ where: { id: params.postId } })",
      "  return new Response(null, { status: 204 })",
      "}",
      "async function verifyCurrentUserHasAccessToPost(postId: string) {",
      helperBody,
      "}",
    );

  it("a same-file helper that reads the session and filters by authorId counts as auth + ownership (taxonomy)", async () => {
    const helper = [
      "  const session = await getServerSession(authOptions)",
      "  const count = await db.post.count({ where: { id: postId, authorId: session?.user.id } })",
      "  return count > 0",
    ].join("\n");
    expect(await ruleIdsFor({ "app/api/posts/[postId]/route.ts": route(helper) })).toEqual([]);
  });

  it("control: a same-file helper that checks nothing does not protect the handler", async () => {
    const ids = await ruleIdsFor({ "app/api/posts/[postId]/route.ts": route("  return postId.length > 0", "await isValidId(params.postId)").replace("isValidId", "looksOk") });
    expect(ids).toContain("AUTH-002");
    expect(ids).toContain("AUTH-003");
  });
});

describe("corpus regressions: AUTH-002 false positives", () => {
  it("supabase.auth.* calls (updateUser, signUp) are not data access", async () => {
    const code = src('"use server";', "export async function updateEmail(formData: FormData) {", "  const supabase = createClient();", "  await supabase.auth.updateUser({ email: String(formData.get('email')) });", "}");
    expect(await ruleIdsFor({ "app/actions.ts": code })).toEqual([]);
  });

  it("control: a real table update in a server action is still flagged", async () => {
    const code = src('"use server";', "export async function rename(name: string) {", "  const supabase = createClient();", '  await supabase.from("profiles").update({ name });', "}");
    expect(await ruleIdsFor({ "app/actions.ts": code })).toEqual(["AUTH-002"]);
  });

  it("sign-in / sign-up server actions are public by design (but may lack a rate limit)", async () => {
    const code = src("export const signIn = validatedAction(schema, async (data) => {", "  const rows = await db.select().from(users).where(eq(users.email, data.email));", "  return rows;", "});");
    const ids = await ruleIdsFor({ "app/(login)/actions.ts": '"use server";\n' + code });
    expect(ids).not.toContain("AUTH-002");
  });

  it("control: a differently named action with the same body is flagged", async () => {
    const code = src('"use server";', "export async function listUsers() {", "  return await db.select().from(users);", "}");
    expect(await ruleIdsFor({ "app/(login)/actions.ts": code })).toEqual(["AUTH-002"]);
  });

  it("a Stripe success redirect that retrieves the checkout session is verified by Stripe", async () => {
    const code = src(
      "export async function GET(request: Request) {",
      "  const sessionId = new URL(request.url).searchParams.get('session_id');",
      "  const session = await stripe.checkout.sessions.retrieve(sessionId!);",
      "  await db.update(teams).set({ plan: session.id });",
      "  return Response.redirect('/dashboard');",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/stripe/checkout/route.ts": code })).toEqual([]);
  });

  it("an availability check route is public by design", async () => {
    const code = src("export async function POST(req: Request) {", "  const { username } = await req.json();", '  const rows = await admin.from("profiles").select("username").eq("username", username);', "  return Response.json({ ok: !rows });", "}");
    expect(await ruleIdsFor({ "app/api/username/available/route.ts": code })).toEqual([]);
  });

  it("control: a lookup route with a similar body but a private name is flagged", async () => {
    const code = src("export async function POST(req: Request) {", "  const { username } = await req.json();", '  const rows = await admin.from("profiles").select("*").eq("username", username);', "  return Response.json(rows);", "}");
    expect(await ruleIdsFor({ "app/api/username/get/route.ts": code })).toEqual(["AUTH-002"]);
  });
});

describe("corpus regressions: AUTH-010 false positives", () => {
  it("an object assembled field by field is an explicit pick, not the request body", async () => {
    const code = src(
      '"use server";',
      "export async function sendRequest(targetId: string, ownerId: string) {",
      "  const insertData: any = { owner_id: ownerId, status: 'pending' };",
      "  insertData.listing_id = targetId;",
      '  await supabase.from("rental_requests").insert(insertData);',
      "}",
    );
    expect((await scan({ "app/actions.ts": code })).filter((f) => f.ruleId === "AUTH-010")).toEqual([]);
    const typed = src(
      '"use server";',
      "export async function signUp(data: any) {",
      "  const newUser: NewUser = { email: data.email, passwordHash: await hash(data.password), role: 'owner' };",
      "  await db.insert(users).values(newUser);",
      "}",
    );
    expect((await scan({ "app/actions.ts": typed })).filter((f) => f.ruleId === "AUTH-010")).toEqual([]);
  });

  it("control: an object that spreads the request body is still mass assignment", async () => {
    const code = src(
      "export async function POST(req: Request) {",
      "  const body = await req.json();",
      "  const data = { ...body, ownerId: 1 };",
      "  await prisma.item.create({ data });",
      "  return Response.json({});",
      "}",
    );
    expect((await scan({ "app/api/items/route.ts": code })).filter((f) => f.ruleId === "AUTH-010")).toHaveLength(1);
  });
});

describe("corpus regressions: AUTH-009 false positives", () => {
  it("a fallback default (|| / ??) or a client display choice is not an authorization decision", async () => {
    const dflt = src('export const roleOf = (user: any) => user.user_metadata?.role || "student";');
    expect((await scan({ "lib/a.ts": dflt })).filter((f) => f.ruleId === "AUTH-009")).toEqual([]);
    const nullish = src('export const roleOf = (user: any) => (user?.user_metadata?.role as string) ?? "student";');
    expect((await scan({ "lib/a.ts": nullish })).filter((f) => f.ruleId === "AUTH-009")).toEqual([]);
    const ui = src('"use client";', 'export function Nav({ user }: any) {', '  const role = user?.user_metadata?.role ?? "student";', '  return role === "admin" ? 1 : 2;', "}");
    expect((await scan({ "components/Nav.tsx": ui })).filter((f) => f.ruleId === "AUTH-009")).toEqual([]);
  });

  it("control: a direct comparison in server code is still critical", async () => {
    const code = src('export const isAdmin = (user: any) => user.user_metadata.role === "admin";');
    const f = (await scan({ "lib/a.ts": code })).filter((x) => x.ruleId === "AUTH-009");
    expect(f.map((x) => x.severity)).toEqual(["critical"]);
  });
});
