import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/auth-auditor/index.js";
import { runScan } from "../../../src/core/orchestrator.js";
import { memContext, memFiles } from "../../helpers/memfs.js";
import { MIDDLEWARE, ruleIdsFor, scan } from "./helpers.js";

describe("AUTH-004 JWT misuse", () => {
  it("flags jwt.decode used without verify", async () => {
    const src = `import jwt from "jsonwebtoken";
export function who(token: string) {
  const claims = jwt.decode(token) as { sub: string };
  return claims.sub;
}
`;
    const f = await scan({ "lib/auth.ts": src });
    expect(f.map((x) => x.ruleId)).toEqual(["AUTH-004"]);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.evidence[0]?.line).toBe(3);
  });

  it("flags jwtDecode in middleware", async () => {
    const src = `import { jwtDecode } from "jwt-decode";
export function middleware(req) {
  const t = jwtDecode(req.cookies.get("token")?.value ?? "");
  if (t.role !== "admin") return Response.redirect("/");
}
`;
    expect(await ruleIdsFor({ "middleware.ts": src })).toContain("AUTH-004");
  });

  it("does not flag jwt-decode in client components for UI display", async () => {
    const src = `"use client";
import { jwtDecode } from "jwt-decode";
export function Name({ t }) { return jwtDecode(t).name; }
`;
    expect(await ruleIdsFor({ "components/Name.tsx": src })).toEqual([]);
  });

  it("does not flag decode when verify is also used in the file", async () => {
    const src = `import jwt from "jsonwebtoken";
export function peek(t: string) { return jwt.decode(t, { complete: true }); }
export function check(t: string) { return jwt.verify(t, process.env.JWT_SECRET!); }
`;
    expect(await ruleIdsFor({ "lib/jwt.ts": src })).toEqual([]);
  });

  it("flags algorithms none as critical", async () => {
    const src = `import jwt from "jsonwebtoken";
export const v = (t: string) => jwt.verify(t, process.env.S!, { algorithms: ["none", "HS256"] });
`;
    const f = await scan({ "lib/jwt.ts": src });
    expect(f.map((x) => [x.ruleId, x.severity])).toEqual([["AUTH-004", "critical"]]);
  });

  it("flags hard-coded secrets in sign and verify and registers the secret", async () => {
    const src = `import jwt from "jsonwebtoken";
export const sign = (u: string) => jwt.sign({ u }, "super-secret-value-123", { expiresIn: "1h" });
export const ver = (t: string) => jwt.verify(t, 'another-hardcoded-secret');
`;
    const ctx = memContext({ "lib/jwt.ts": src });
    const f = await agent.run(ctx);
    expect(f.map((x) => x.ruleId)).toEqual(["AUTH-004", "AUTH-004"]);
    expect(f.every((x) => x.cwe === "CWE-798")).toBe(true);
    expect(ctx.secrets.has("super-secret-value-123")).toBe(true);
    expect(f[0]?.evidence[0]?.snippet).not.toContain("super-secret-value-123");
  });

  it("flags jose with a literal secret", async () => {
    const src = `import { jwtVerify } from "jose";
export const v = (t: string) => jwtVerify(t, new TextEncoder().encode("my-literal-secret"));
`;
    expect(await ruleIdsFor({ "lib/jose.ts": src })).toEqual(["AUTH-004"]);
  });

  it("does not flag env based secrets", async () => {
    const src = `import jwt from "jsonwebtoken";
export const sign = (u: string) => jwt.sign({ u }, process.env.JWT_SECRET!, { algorithm: "HS256", expiresIn: "1h" });
export const ver = (t: string) => jwt.verify(t, \`\${process.env.JWT_SECRET}\`, { algorithms: ["HS256"] });
`;
    expect(await ruleIdsFor({ "lib/jwt.ts": src })).toEqual([]);
  });
});

describe("inline suppression is handled centrally by the orchestrator", () => {
  const BODY = `export async function DELETE(req: Request) {
  await prisma.item.deleteMany();
  return Response.json({});
}
`;
  const run = (src: string) =>
    runScan({ mode: "static", targetLabel: ".", files: memFiles({ "app/api/i/route.ts": src }), agents: [agent] });

  it("the agent itself no longer drops commented findings", async () => {
    expect(await ruleIdsFor({ "app/api/i/route.ts": `// whsquad-ignore AUTH-002
${BODY}` })).toEqual(["AUTH-002"]);
  });

  it("a directive on the previous line moves the finding to report.suppressed", async () => {
    const report = await run(`// whsquad-ignore AUTH-002 -- internal job
${BODY}`);
    expect(report.findings.filter((f) => f.ruleId === "AUTH-002")).toEqual([]);
    expect((report.suppressed ?? []).map((s) => s.ruleId)).toEqual(["AUTH-002"]);
  });

  it("a directive on the same line suppresses too", async () => {
    const report = await run(BODY.replace("DELETE(req: Request) {", "DELETE(req: Request) { // whsquad-ignore AUTH-002"));
    expect((report.suppressed ?? []).map((s) => s.ruleId)).toEqual(["AUTH-002"]);
  });

  it("does not suppress a different rule id", async () => {
    const report = await run(`// whsquad-ignore AUTH-005
${BODY}`);
    expect(report.findings.map((f) => f.ruleId)).toEqual(["AUTH-002"]);
    expect(report.suppressed ?? []).toEqual([]);
  });

  it("supports comma separated ids", async () => {
    const report = await run(`// whsquad-ignore AUTH-005, AUTH-002
${BODY}`);
    expect((report.suppressed ?? []).map((s) => s.ruleId)).toEqual(["AUTH-002"]);
  });
});

describe("finding shape and robustness", () => {
  it("produces complete findings", async () => {
    const src = `export async function DELETE(req: Request) {\n  await prisma.item.deleteMany();\n  return Response.json({});\n}\n`;
    const [f] = await scan({ "app/api/i/route.ts": src });
    expect(f?.agentId).toBe("auth-auditor");
    expect(f?.cwe).toBe("CWE-306");
    expect(f?.fix.agentPrompt).toContain("app/api/i/route.ts");
    expect(f?.fix.agentPrompt).toContain("1");
    expect(f?.fix.references.length).toBeGreaterThan(0);
    expect(f?.fix.patch?.diff ?? f?.fix.config).toBeTruthy();
    expect(f?.evidence[0]?.snippet.length).toBeLessThanOrEqual(200);
    expect(f?.verify.ruleId).toBe("AUTH-002");
  });

  it("truncates huge single-line evidence", async () => {
    const pad = "x".repeat(500);
    const src = `export async function DELETE() { await prisma.item.deleteMany(); /* ${pad} */ }`;
    const [f] = await scan({ "app/api/i/route.ts": src });
    expect(f?.evidence[0]?.snippet.length).toBeLessThanOrEqual(200);
  });

  it("declares id, name and static mode", () => {
    expect(agent.id).toBe("auth-auditor");
    expect(agent.modes).toEqual(["static"]);
  });

  it("returns nothing for an empty project and for non-source files", async () => {
    expect(await scan({})).toEqual([]);
    expect(await scan({ "README.md": "if (!user) navigate('/login')" })).toEqual([]);
  });

  it("skips node_modules, tests, declaration files and git-ignored files", async () => {
    const bad = `export async function DELETE() { await prisma.item.deleteMany(); }`;
    const f = await scan({
      "node_modules/x/app/api/a/route.ts": bad,
      "app/api/a/route.test.ts": bad,
      "app/api/b/route.d.ts": bad,
      ".gitignore": "generated/\n",
      "generated/app/api/c/route.ts": bad,
    });
    expect(f).toEqual([]);
  });

  it("ignores patterns inside comments and strings", async () => {
    const src = `// jwt.decode(token) is unsafe, localStorage.getItem("isAdmin") === "true"\nconst s = "jwt.decode(x)";\n`;
    expect(await ruleIdsFor({ "lib/x.ts": src })).toEqual([]);
  });

  it("tolerates unreadable files", async () => {
    const ctx = memContext({ "a.ts": "x" });
    const files = { ...ctx.files, paths: ["missing.ts"] };
    expect(await agent.run({ ...ctx, files })).toEqual([]);
  });
});

describe("clean baseline: well-written Next.js app", () => {
  const files: Record<string, string> = {
    "middleware.ts": `import { type NextRequest } from "next/server";
import { updateSession } from "@/lib/supabase/middleware";
export async function middleware(request: NextRequest) { return await updateSession(request); }
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|login|signup).*)"] };
`,
    "lib/supabase/server.ts": `import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
export function createClient() {
  const store = cookies();
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}
`,
    "app/dashboard/page.tsx": `import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
export default async function Page() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");
  const { data } = await supabase.from("projects").select("*").eq("owner_id", user.id);
  return <ul>{data?.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
`,
    "app/login/page.tsx": `"use client";
import { useRouter } from "next/navigation";
export default function Login() {
  const router = useRouter();
  async function submit() { await signIn(); router.push("/dashboard"); }
  return <button onClick={submit}>Sign in</button>;
}
`,
    "app/api/projects/[id]/route.ts": `import { createClient } from "@/lib/supabase/server";
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await supabase.from("projects").select("*").eq("id", params.id).eq("owner_id", user.id).single();
  return Response.json(data);
}
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  await supabase.from("projects").delete().match({ id: params.id, owner_id: user.id });
  return Response.json({ ok: true });
}
`,
    "app/api/health/route.ts": `export async function GET() { return Response.json({ ok: true }); }\n`,
    "app/api/webhooks/stripe/route.ts": `import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export async function POST(req: Request) {
  const raw = await req.text();
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response("bad signature", { status: 400 });
  }
  if (event.type === "checkout.session.completed") {
    await admin.from("subscriptions").upsert({ id: event.id, status: "active" });
  }
  return new Response("ok");
}
`,
    "app/actions.ts": `"use server";
import { createClient } from "@/lib/supabase/server";
export async function renameProject(id: string, name: string) {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("unauthorized");
  await supabase.from("projects").update({ name }).eq("id", id).eq("owner_id", user.id);
}
`,
    "lib/token.ts": `import jwt from "jsonwebtoken";
export const verify = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ["HS256"] });
`,
    "components/Theme.tsx": `"use client";
export function Theme() { return localStorage.getItem("theme") === "dark" ? "dark" : "light"; }
`,
  };

  it("produces zero findings", async () => {
    expect(await scan(files)).toEqual([]);
  });

  it("stays clean without middleware when server handlers verify sessions, despite a client guard", async () => {
    const { "middleware.ts": _mw, ...rest } = files;
    void _mw;
    const noMw = { ...rest, "components/Guard.tsx": `"use client";\nexport function G({ user, router }) { useEffect(() => { if (!user) router.push("/login"); }, [user]); return null; }\n` };
    // Server auth checks still exist, so the client guard is not the only layer.
    expect(await ruleIdsFor(noMw)).toEqual([]);
    void MIDDLEWARE;
  });
});
