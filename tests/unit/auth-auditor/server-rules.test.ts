import { describe, expect, it } from "vitest";
import { MIDDLEWARE, NOOP_MIDDLEWARE, ruleIdsFor, scan } from "./helpers.js";

describe("AUTH-002 unauthenticated route handlers and server actions", () => {
  const DELETE_ROUTE = `import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.URL!, process.env.KEY!);
export async function DELETE(req: Request) {
  const { id } = await req.json();
  await supabase.from("items").delete().eq("id", id);
  return Response.json({ ok: true });
}
`;

  it("flags a route handler that mutates data without any auth check", async () => {
    const f = await scan({ "app/api/items/route.ts": DELETE_ROUTE });
    const hit = f.find((x) => x.ruleId === "AUTH-002");
    expect(hit?.severity).toBe("high");
    expect(hit?.confidence).toBe("high");
    expect(hit?.evidence[0]?.line).toBe(3);
    expect(hit?.explanation).toMatch(/logged-out/i);
  });

  it("flags a Server Action with inline use server", async () => {
    const src = `import { prisma } from "@/lib/prisma";
export async function removePost(id: string) {
  "use server";
  await prisma.post.delete({ where: { id } });
}
`;
    expect(await ruleIdsFor({ "app/actions.ts": src })).toContain("AUTH-002");
  });

  it("flags every exported function of a file-level use server module separately", async () => {
    const src = `"use server";
import { db } from "@/db";
import { getUser } from "@/auth";
export async function safe() { const u = await getUser(); return db.select().from(t).where(eq(t.owner, u.id)); }
export async function unsafe(name: string) { await db.insert(t).values({ name }); }
`;
    const f = await scan({ "app/actions.ts": src });
    expect(f.filter((x) => x.ruleId === "AUTH-002")).toHaveLength(1);
    expect(f[0]?.evidence[0]?.line).toBe(5);
  });

  it("flags pages/api handlers", async () => {
    const src = `export default async function handler(req, res) {
  const rows = await db.query("select * from orders");
  res.json(rows);
}
`;
    expect(await ruleIdsFor({ "pages/api/orders.ts": src })).toEqual(["AUTH-002"]);
  });

  it("flags only the unprotected method", async () => {
    const src = `import { auth } from "@clerk/nextjs/server";
export async function GET() { const { userId } = auth(); return Response.json(await prisma.todo.findMany({ where: { userId } })); }
export async function POST(req: Request) { const b = await req.json(); await prisma.todo.create({ data: b }); return Response.json({}); }
`;
    const f = await scan({ "app/api/todos/route.ts": src });
    expect(f.filter((x) => x.ruleId === "AUTH-002").map((x) => [x.ruleId, x.evidence[0]?.line])).toEqual([["AUTH-002", 3]]);
  });

  it("flags const-arrow handlers", async () => {
    const src = `export const POST = async (req: Request) => {
  await prisma.user.update({ where: { id: 1 }, data: { admin: true } });
  return Response.json({});
};
`;
    expect(await ruleIdsFor({ "app/api/make-admin/route.ts": src })).toEqual(["AUTH-002"]);
  });

  it("uses medium confidence for read-only handlers", async () => {
    const src = `export async function GET() { return Response.json(await prisma.post.findMany()); }\n`;
    const f = await scan({ "app/api/posts/route.ts": src });
    expect(f[0]?.confidence).toBe("medium");
  });

  it("does not flag handlers that call getUser", async () => {
    const src = DELETE_ROUTE.replace(
      "const { id } = await req.json();",
      "const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response(null, { status: 401 });\n  const { id } = await req.json();",
    ).replace('.eq("id", id)', '.eq("id", id).eq("user_id", user.id)');
    expect(await ruleIdsFor({ "app/api/items/route.ts": src })).toEqual([]);
  });

  it.each([
    ["app/api/health/route.ts"],
    ["app/api/login/route.ts"],
    ["app/api/auth/signup/route.ts"],
    ["app/og/route.ts"],
    ["src/app/api/ping/route.ts"],
  ])("does not flag public-by-design route %s", async (path) => {
    expect(await ruleIdsFor({ [path]: DELETE_ROUTE })).toEqual([]);
  });

  it("does not flag handlers that touch no data", async () => {
    const src = `export async function GET() { return Response.json({ ok: true }); }\n`;
    expect(await ruleIdsFor({ "app/api/version/route.ts": src })).toEqual([]);
  });

  it("does not flag signed webhooks", async () => {
    const src = `import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_KEY!);
export async function POST(req: Request) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature")!, process.env.WH!);
  if (event.type === "checkout.session.completed") { await db.orders.update({ where: { id: "1" }, data: { paid: true } }); }
  return new Response("ok");
}
`;
    expect(await ruleIdsFor({ "app/api/webhooks/stripe/route.ts": src })).toEqual([]);
  });

  it("does not flag cron routes guarded by CRON_SECRET bearer", async () => {
    const src = `export async function GET(req: Request) {
  if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response(null, { status: 401 });
  await db.query("delete from sessions where expired");
  return new Response("ok");
}
`;
    expect(await ruleIdsFor({ "app/api/cron/route.ts": src })).toEqual([]);
  });

  it("does not flag handlers wrapped by an auth helper", async () => {
    const src = `export const POST = withAuth(async (req, user) => { await db.insert(t).values({ owner: user.id }); return Response.json({}); });\n`;
    expect(await ruleIdsFor({ "app/api/x/route.ts": src })).toEqual([]);
  });

  it("downgrades to medium confidence when an authenticating middleware covers the route", async () => {
    const mw = MIDDLEWARE.replace("/dashboard/:path*", "/api/:path*");
    const f = await scan({ "middleware.ts": mw, "app/api/items/route.ts": DELETE_ROUTE });
    expect(f.find((x) => x.ruleId === "AUTH-002")?.confidence).toBe("medium");
  });

  it("does not downgrade for a no-op middleware, even with a matching matcher", async () => {
    const noop = NOOP_MIDDLEWARE.replace("/dashboard/:path*", "/api/:path*");
    const f = await scan({ "middleware.ts": noop, "app/api/items/route.ts": DELETE_ROUTE });
    expect(f.find((x) => x.ruleId === "AUTH-002")?.confidence).toBe("high");
    const empty = `export function middleware() {}
export const config = { matcher: ["/api/:path*"] };
`;
    const g = await scan({ "middleware.ts": empty, "app/api/items/route.ts": DELETE_ROUTE });
    expect(g.find((x) => x.ruleId === "AUTH-002")?.confidence).toBe("high");
  });

  it("does not downgrade when the authenticating middleware matcher excludes the route", async () => {
    const f = await scan({ "middleware.ts": MIDDLEWARE, "app/api/items/route.ts": DELETE_ROUTE });
    expect(f.find((x) => x.ruleId === "AUTH-002")?.confidence).toBe("high");
  });
});

describe("AUTH-003 IDOR-prone handlers", () => {
  const head = `import { createClient } from "@/lib/supabase/server";
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
`;

  it("flags supabase lookup by params.id with no ownership filter", async () => {
    const src = `${head}  const { data } = await supabase.from("invoices").select("*").eq("id", params.id).single();
  return Response.json(data);
}
`;
    const f = await scan({ "app/api/invoices/[id]/route.ts": src });
    expect(f.map((x) => x.ruleId)).toEqual(["AUTH-003"]);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.evidence[0]?.line).toBe(6);
    expect(f[0]?.cwe).toBe("CWE-639");
  });

  it("passes when an ownership filter is present", async () => {
    const src = `${head}  const { data } = await supabase.from("invoices").select("*").eq("id", params.id).eq("user_id", user.id).single();
  return Response.json(data);
}
`;
    expect(await ruleIdsFor({ "app/api/invoices/[id]/route.ts": src })).toEqual([]);
  });

  it("flags prisma where id from request body", async () => {
    const src = `import { getServerSession } from "next-auth";
export async function PATCH(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  await prisma.post.update({ where: { id: body.id }, data: { title: body.title } });
  return Response.json({});
}
`;
    expect(await ruleIdsFor({ "app/api/posts/route.ts": src })).toEqual(["AUTH-003"]);
  });

  it("flags destructured ids and shorthand where", async () => {
    const src = `import { auth } from "@/auth";
export async function DELETE(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const { searchParams } = new URL(req.url);
  const postId = searchParams.get("postId");
  await prisma.post.delete({ where: { id: postId } });
  return Response.json({});
}
`;
    expect(await ruleIdsFor({ "app/api/posts/route.ts": src })).toEqual(["AUTH-003"]);
  });

  it("flags userId taken from the request body", async () => {
    const src = `import { auth } from "@/auth";
export async function POST(req: Request) {
  await auth();
  const { userId } = await req.json();
  const profile = await prisma.profile.findFirst({ where: { userId } });
  return Response.json(profile);
}
`;
    expect(await ruleIdsFor({ "app/api/profile/route.ts": src })).toEqual(["AUTH-003"]);
  });

  it("does not treat userId from auth() as attacker-controlled", async () => {
    const src = `import { auth } from "@clerk/nextjs/server";
export async function GET() {
  const { userId } = auth();
  if (!userId) return new Response(null, { status: 401 });
  const profile = await prisma.profile.findFirst({ where: { userId } });
  return Response.json(profile);
}
`;
    expect(await ruleIdsFor({ "app/api/profile/route.ts": src })).toEqual([]);
  });

  it("passes prisma where with session ownership", async () => {
    const src = `import { auth } from "@/auth";
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  await prisma.post.deleteMany({ where: { id: params.id, authorId: session.user.id } });
  return Response.json({});
}
`;
    expect(await ruleIdsFor({ "app/api/posts/[id]/route.ts": src })).toEqual([]);
  });

  it("passes when ownership is verified after fetching", async () => {
    const src = `import { auth } from "@/auth";
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const post = await prisma.post.findUnique({ where: { id: params.id } });
  if (post?.authorId !== session.user.id) return new Response(null, { status: 403 });
  await prisma.post.delete({ where: { id: params.id } });
  return Response.json({});
}
`;
    expect(await ruleIdsFor({ "app/api/posts/[id]/route.ts": src })).toEqual([]);
  });

  it("ignores inserts that merely carry an id-like value", async () => {
    const src = `import { auth } from "@/auth";
export async function POST(req: Request) {
  const session = await auth();
  const body = await req.json();
  await prisma.log.create({ data: { itemId: body.itemId } });
  return Response.json({});
}
`;
    expect(await ruleIdsFor({ "app/api/log/route.ts": src })).toEqual([]);
  });

  it("flags server actions that take an id argument via formData", async () => {
    const src = `"use server";
import { auth } from "@/auth";
export async function removeItem(formData: FormData) {
  const session = await auth();
  if (!session) throw new Error("no");
  await db.item.delete({ where: { id: formData.get("id") as string } });
}
`;
    expect(await ruleIdsFor({ "app/actions.ts": src })).toEqual(["AUTH-003"]);
  });
});

describe("AUTH-006 stripe webhook without signature verification", () => {
  it("flags a webhook that trusts the parsed body", async () => {
    const src = `export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await prisma.user.update({ where: { id: event.data.object.client_reference_id }, data: { plan: "pro" } });
  }
  return new Response("ok");
}
`;
    const f = await scan({ "app/api/stripe/webhook/route.ts": src });
    const hit = f.find((x) => x.ruleId === "AUTH-006");
    expect(hit?.severity).toBe("critical");
    expect(hit?.evidence[0]?.line).toBe(2);
    expect(f.some((x) => x.ruleId === "AUTH-002")).toBe(true);
  });

  it("flags pages/api express-style bodies", async () => {
    const src = `import Stripe from "stripe";
export default async function handler(req, res) {
  const event = req.body;
  switch (event.type) {
    case "invoice.paid": grantAccess(event); break;
  }
  res.json({ received: true });
}
`;
    expect(await ruleIdsFor({ "pages/api/stripe-hook.ts": src })).toContain("AUTH-006");
  });

  it("passes when constructEvent is used", async () => {
    const src = `import Stripe from "stripe";
const stripe = new Stripe(process.env.K!);
export async function POST(req: Request) {
  const body = await req.text();
  const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, process.env.WH!);
  if (event.type === "invoice.paid") grantAccess(event);
  return new Response("ok");
}
`;
    expect(await ruleIdsFor({ "app/api/stripe/webhook/route.ts": src })).toEqual([]);
  });

  it("passes when constructEventAsync is used", async () => {
    const src = `export async function POST(req: Request) {
  const event = await stripe.webhooks.constructEventAsync(await req.text(), sig, secret);
  if (event.type === "invoice.paid") grantAccess(event);
  return new Response("ok");
}
`;
    expect(await ruleIdsFor({ "app/api/stripe/webhook/route.ts": src })).toEqual([]);
  });

  it("does not flag non-stripe handlers with event.type", async () => {
    const src = `export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "click") track(event);
  return new Response("ok");
}
`;
    expect(await ruleIdsFor({ "app/api/track/route.ts": src })).toEqual([]);
  });
});
