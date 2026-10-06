import { describe, expect, it } from "vitest";
import { toFinding, docFor } from "../../../src/agents/auth-auditor/report.js";
import { RULES } from "../../../src/agents/auth-auditor/rules.meta.js";
import { ruleIdsFor, scan } from "./helpers.js";

const src = (...lines: string[]): string => lines.join("\n") + "\n";

describe("engine migration: Express/Hono/Fastify/Koa coverage", () => {
  it("flags an unauthenticated Express handler that touches data (AUTH-002)", async () => {
    const code = src(
      'import express from "express";',
      "const app = express();",
      'app.get("/orders", async (req, res) => {',
      '  const rows = await db.query("select * from orders");',
      "  res.json(rows);",
      "});",
    );
    expect(await ruleIdsFor({ "server/index.ts": code })).toEqual(["AUTH-002"]);
  });

  it("control: Express handler with a route-level auth middleware is clean", async () => {
    const code = src(
      'import express from "express";',
      "const app = express();",
      'app.get("/orders", requireAuth, async (req, res) => {',
      '  const rows = await db.query("select * from orders");',
      "  res.json(rows);",
      "});",
    );
    expect(await ruleIdsFor({ "server/index.ts": code })).toEqual([]);
  });

  it("guards are evaluated per unit: auth in one Express route does not protect another", async () => {
    const code = src(
      'import express from "express";',
      "const app = express();",
      'app.get("/a", requireAuth, async (req, res) => { res.json(await db.query("select 1")); });',
      'app.get("/b", async (req, res) => { res.json(await db.query("select 2")); });',
    );
    const f = await scan({ "server/index.ts": code });
    expect(f.map((x) => [x.ruleId, x.evidence[0]?.line])).toEqual([["AUTH-002", 4]]);
  });

  it("flags IDOR in a Hono handler (AUTH-003)", async () => {
    const code = src(
      'import { Hono } from "hono";',
      "const app = new Hono();",
      'app.get("/items/:id", async (c) => {',
      "  const user = await getCurrentUser(c);",
      '  const row = await prisma.item.findUnique({ where: { id: c.req.param("id") } });',
      "  return c.json(row);",
      "});",
    );
    expect(await ruleIdsFor({ "src/server.ts": code })).toEqual(["AUTH-003"]);
  });

  it("works for semicolon-less code (statement scanning)", async () => {
    const code = src(
      'import { auth } from "@/auth"',
      "export async function DELETE(req: Request, { params }: { params: { id: string } }) {",
      "  const session = await auth()",
      "  if (!session) return new Response(null, { status: 401 })",
      '  await prisma.post.delete({ where: { id: params.id } })',
      "  return Response.json({})",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/posts/[id]/route.ts": code })).toEqual(["AUTH-003"]);
  });
});

describe("engine migration: strings and comments never count, ${} does", () => {
  it("an auth call mentioned in a string or comment does not protect a handler", async () => {
    const code = src(
      "export async function DELETE(req: Request) {",
      '  // const user = await getUser() would go here',
      '  const hint = "await getUser()";',
      "  await prisma.item.deleteMany();",
      "  return Response.json({ hint });",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/i/route.ts": code })).toEqual(["AUTH-002"]);
  });

  it("a data call that only appears inside a comment does not create AUTH-002", async () => {
    const code = src("export async function GET() {", "  // prisma.user.findMany()", "  return Response.json({ ok: true });", "}");
    expect(await ruleIdsFor({ "app/api/v/route.ts": code })).toEqual([]);
  });

  it("a match inside a template interpolation counts as code", async () => {
    const code = src(
      "export async function POST(req: Request) {",
      "  const msg = `done: ${await prisma.item.deleteMany()}`;",
      "  return Response.json({ msg });",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/i/route.ts": code })).toEqual(["AUTH-002"]);
  });

  it("an auth call inside a template interpolation counts as a guard", async () => {
    const code = src(
      "export async function GET() {",
      "  const label = `hi ${(await getCurrentUser()).name}`;",
      "  return Response.json({ label, rows: await prisma.item.findMany() });",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/i/route.ts": code })).toEqual([]);
  });
});

describe("bug fixes from review", () => {
  it("OWNER_REF: currentUser.id, authUser.id and profile.id (from an auth call) count as ownership", async () => {
    for (const owner of ["currentUser.id", "authUser.id"]) {
      const code = src(
        "export async function GET(req: Request, { params }: { params: { id: string } }) {",
        `  const ${owner.split(".")[0]} = await getCurrentUser();`,
        `  const r = await prisma.doc.findFirst({ where: { id: params.id, ownerId: ${owner} } });`,
        "  return Response.json(r);",
        "}",
      );
      expect(await ruleIdsFor({ "app/api/d/[id]/route.ts": code }), owner).toEqual([]);
    }
    const profile = src(
      "export async function GET(req: Request, { params }: { params: { id: string } }) {",
      "  const profile = await getServerProfile();",
      '  const r = await supabase.from("docs").select("*").eq("id", params.id).eq("user_id", profile.id).single();',
      "  return Response.json(r);",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/d/[id]/route.ts": profile })).toEqual([]);
  });

  it("OWNER_REF: { userId: userId } counts when userId came from an auth call", async () => {
    const code = src(
      "export async function GET(req: Request, { params }: { params: { id: string } }) {",
      "  const { userId } = auth();",
      "  const r = await prisma.doc.findFirst({ where: { id: params.id, userId: userId } });",
      "  return Response.json(r);",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/d/[id]/route.ts": code })).toEqual([]);
  });

  it("control: a userId taken from the request body is still IDOR", async () => {
    const code = src(
      "export async function GET(req: Request) {",
      "  await auth();",
      "  const { userId } = await req.json();",
      "  const r = await prisma.doc.findFirst({ where: { userId: userId } });",
      "  return Response.json(r);",
      "}",
    );
    expect(await ruleIdsFor({ "app/api/d/route.ts": code })).toEqual(["AUTH-003"]);
  });

  it("AUTH-004 finds a hard-coded secret when the payload has nested braces", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      'export const t = (u: string) => jwt.sign({ sub: u, meta: { roles: ["a"], org: { id: 1 } } }, "nested-brace-secret-1", { expiresIn: "1h" });',
    );
    const f = await scan({ "lib/jwt.ts": code });
    expect(f.filter((x) => x.ruleId === "AUTH-004")).toHaveLength(1);
    expect(f[0]?.evidence[0]?.snippet).not.toContain("nested-brace-secret-1");
  });

  it("AUTH-004 flags process.env.JWT_SECRET || \"literal\" fallback as hard-coded (high)", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      'export const v = (t: string) => jwt.verify(t, process.env.JWT_SECRET || "fallback-secret-xyz");',
    );
    const f = await scan({ "lib/jwt.ts": code });
    expect(f.map((x) => [x.ruleId, x.severity])).toEqual([["AUTH-004", "high"]]);
  });

  it("AUTH-004 follows a const holding an env fallback", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      'const SECRET = process.env.JWT_SECRET ?? "dev-secret-123";',
      'export const sign = (u: string) => jwt.sign({ u }, SECRET, { expiresIn: "1h" });',
    );
    expect((await ruleIdsFor({ "lib/jwt.ts": code }))).toEqual(["AUTH-004"]);
  });

  it("AUTH-004 control: env secret without fallback is clean", async () => {
    const code = src('import jwt from "jsonwebtoken";', 'export const v = (t: string) => jwt.verify(t, process.env.JWT_SECRET!);');
    expect(await ruleIdsFor({ "lib/jwt.ts": code })).toEqual([]);
  });

  it("AUTH-004: an unrelated .verify( (zod-like) does not hide jwt.decode", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      "export function who(token: string) {",
      "  const ok = schema.verify(token);",
      "  return jwt.decode(token);",
      "}",
    );
    expect(await ruleIdsFor({ "lib/who.ts": code })).toEqual(["AUTH-004"]);
  });

  it("AUTH-004: verify of a different token does not hide decode of this one", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      "export function a(tokenA: string) { return jwt.decode(tokenA); }",
      "export function b(tokenB: string) { return jwt.verify(tokenB, process.env.S!); }",
    );
    expect(await ruleIdsFor({ "lib/a.ts": code })).toEqual(["AUTH-004"]);
  });

  it("AUTH-004 control: decode plus verify of the same token in one function is clean", async () => {
    const code = src(
      'import jwt from "jsonwebtoken";',
      "export function a(token: string) {",
      "  const claims = jwt.verify(token, process.env.S!);",
      "  const meta = jwt.decode(token);",
      "  return { claims, meta };",
      "}",
    );
    expect(await ruleIdsFor({ "lib/a.ts": code })).toEqual([]);
  });

  it("docFor never throws for any rule id or variant", () => {
    for (const r of RULES) {
      for (const variant of [undefined, "none", "nonsense", "decode"]) {
        expect(() => docFor({ ruleId: r.id, variant })).not.toThrow();
        const f = toFinding({ ruleId: r.id, file: "a.ts", line: 1, snippet: "x", ...(variant ? { variant } : {}) });
        expect(f.fix.agentPrompt).toContain("a.ts");
        expect(f.fix.references.length + f.explanation.length).toBeGreaterThan(0);
      }
    }
    expect(() => docFor({ ruleId: "AUTH-999" })).not.toThrow();
  });

  it("AUTH-004 plain variant (no variant given) still renders", () => {
    expect(toFinding({ ruleId: "AUTH-004", file: "a.ts", line: 3, snippet: "jwt.decode(t)" }).title).toMatch(/JWT/);
  });
});
