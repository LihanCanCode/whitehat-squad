import { describe, expect, it } from "vitest";
import { MIDDLEWARE, NOOP_MIDDLEWARE, ruleIdsFor, scan } from "./helpers.js";

const DASHBOARD = `import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  useEffect(() => {
    if (!user) navigate("/login");
  }, [user]);
  return <div>secret stuff</div>;
}
`;

/** A server route that touches no data: the app has its own server, so a client-only guard matters. */
const API = { "app/api/health/route.ts": "export async function GET() { return Response.json({ ok: true }); }\n" };

describe("AUTH-001 client-only route protection", () => {
  it("stays quiet in a single-page app with no server handlers of its own (public-repo study)", async () => {
    expect(await ruleIdsFor({ "src/pages/Dashboard.tsx": DASHBOARD })).toEqual([]);
  });

  it("flags a useEffect redirect when the project has no middleware or server auth", async () => {
    const f = await scan({ ...API, "src/pages/Dashboard.tsx": DASHBOARD });
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("AUTH-001");
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.evidence[0]?.line).toBe(8);
    expect(f[0]?.evidence[0]?.file).toBe("src/pages/Dashboard.tsx");
  });

  it("flags a <Navigate> guard", async () => {
    const src = `import { Navigate } from "react-router-dom";
export function Guard({ session, children }) {
  if (!session) return <Navigate to="/login" />;
  return children;
}
`;
    expect(await ruleIdsFor({ ...API, "src/Guard.tsx": src })).toEqual(["AUTH-001"]);
  });

  it("flags router.push inside useEffect in a next client component", async () => {
    const src = `"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
export default function Page({ session }) {
  const router = useRouter();
  useEffect(() => { if (!session) { router.push("/login"); } }, [session]);
  return null;
}
`;
    expect(await ruleIdsFor({ ...API, "app/account/page.tsx": src })).toEqual(["AUTH-001"]);
  });

  it("is skipped when a middleware file exists", async () => {
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": MIDDLEWARE })).toEqual([]);
  });

  it("is skipped when src/middleware.ts exists", async () => {
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "src/middleware.ts": MIDDLEWARE })).toEqual([]);
  });

  it("is NOT skipped by a no-op middleware (empty middleware() disables nothing)", async () => {
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": NOOP_MIDDLEWARE })).toEqual(["AUTH-001"]);
    const empty = `export function middleware() {}
export const config = { matcher: ["/dashboard/:path*"] };
`;
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": empty })).toEqual(["AUTH-001"]);
  });

  it("is NOT skipped when the authenticating middleware matcher does not cover the page", async () => {
    const other = MIDDLEWARE.replace("/dashboard/:path*", "/admin/:path*");
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": other })).toEqual(["AUTH-001"]);
  });

  it("is skipped when a catch-all matcher covers the page", async () => {
    const all = MIDDLEWARE.replace('["/dashboard/:path*"]', '["/((?!_next/static|favicon.ico).*)"]');
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": all })).toEqual([]);
  });

  it("treats delegation to an auth helper (updateSession, clerkMiddleware) as authenticating", async () => {
    const delegate = `import { updateSession } from "@/lib/supabase/middleware";
export async function middleware(r: Request) { return await updateSession(r); }
export const config = { matcher: ["/dashboard/:path*"] };
`;
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": delegate })).toEqual([]);
    const clerk = `import { clerkMiddleware } from "@clerk/nextjs/server";
export default clerkMiddleware();
export const config = { matcher: ["/dashboard(.*)"] };
`;
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "middleware.ts": clerk })).toEqual([]);
  });

  it("is skipped when server-side session checks exist", async () => {
    const route = `import { createClient } from "@/lib/supabase/server";
export async function GET() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({}, { status: 401 });
  return Response.json({ ok: true });
}
`;
    expect(await ruleIdsFor({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "app/api/me/route.ts": route })).toEqual([]);
  });

  it("does not flag unrelated redirects", async () => {
    const src = `import { useEffect } from "react";
export default function Done({ saved, router }) {
  useEffect(() => { if (saved) router.push("/done"); }, [saved]);
  return null;
}
`;
    expect(await ruleIdsFor({ "src/Done.tsx": src })).toEqual([]);
  });

  it("does not flag server component redirect()", async () => {
    const src = `import { redirect } from "next/navigation";
import { getUser } from "@/lib/auth";
export default async function Page() {
  const user = await getUser();
  if (!user) redirect("/login");
  return null;
}
`;
    expect(await ruleIdsFor({ "app/dash/page.tsx": src })).toEqual([]);
  });

  it("has medium confidence when no unprotected server handlers exist", async () => {
    const f = await scan({ ...API, "src/pages/Dashboard.tsx": DASHBOARD });
    expect(f[0]?.confidence).toBe("medium");
  });

  it("has high confidence when an unauthenticated data route exists", async () => {
    const route = `export async function GET() { const r = await db.query("select * from t"); return Response.json(r); }`;
    const f = await scan({ ...API, "src/pages/Dashboard.tsx": DASHBOARD, "app/api/t/route.ts": route });
    expect(f.find((x) => x.ruleId === "AUTH-001")?.confidence).toBe("high");
  });
});

describe("AUTH-005 role from client-controlled storage", () => {
  it("flags localStorage isAdmin used in a condition", async () => {
    const src = `export function Admin() {
  if (localStorage.getItem("isAdmin") === "true") { return <Panel />; }
  return null;
}
`;
    const f = await scan({ "src/Admin.tsx": src });
    expect(f.map((x) => x.ruleId)).toEqual(["AUTH-005"]);
    expect(f[0]?.severity).toBe("high");
  });

  it("flags a stored variable later used as a gate", async () => {
    const src = `export function A() {
  const role = sessionStorage.getItem("role");
  return role === "admin" ? <Panel /> : null;
}
`;
    expect(await ruleIdsFor({ "src/A.tsx": src })).toEqual(["AUTH-005"]);
  });

  it("flags JSON.parse of stored user role", async () => {
    const src = `const ok = JSON.parse(localStorage.getItem("user") || "{}").role === "admin";\n`;
    expect(await ruleIdsFor({ "src/a.ts": src })).toEqual(["AUTH-005"]);
  });

  it("flags cookie role used on the server", async () => {
    const src = `import { cookies } from "next/headers";
export async function GET() {
  if (cookies().get("role")?.value === "admin") { return new Response("ok"); }
  return new Response("no", { status: 403 });
}
`;
    expect(await ruleIdsFor({ "app/admin/route.ts": src })).toContain("AUTH-005");
  });

  it("flags Cookies.get plan gate", async () => {
    const src = `import Cookies from "js-cookie";\nif (Cookies.get("plan") !== "free") { unlock(); }\n`;
    expect(await ruleIdsFor({ "src/p.ts": src })).toEqual(["AUTH-005"]);
  });

  it("ignores unrelated storage keys", async () => {
    const src = `if (localStorage.getItem("theme") === "dark") { dark(); }\n`;
    expect(await ruleIdsFor({ "src/t.ts": src })).toEqual([]);
  });

  it("ignores role values that never gate anything", async () => {
    const src = `const role = localStorage.getItem("role");\nlogIt("x");\n`;
    expect(await ruleIdsFor({ "src/t.ts": src })).toEqual([]);
  });
});

describe("AUTH-007 service_role in client code", () => {
  const CLIENT = `"use client";
import { createClient } from "@supabase/supabase-js";
export const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
`;
  it("flags a 'use client' file", async () => {
    const f = await scan({ "app/lib/sb.ts": CLIENT });
    expect(f.map((x) => x.ruleId)).toEqual(["AUTH-007"]);
    expect(f[0]?.severity).toBe("critical");
    expect(f[0]?.evidence[0]?.line).toBe(3);
  });

  it("flags files under src/components", async () => {
    const src = CLIENT.replace('"use client";\n', "");
    expect(await ruleIdsFor({ "src/components/sb.ts": src })).toEqual(["AUTH-007"]);
  });

  it("flags non-api pages", async () => {
    const src = CLIENT.replace('"use client";\n', "");
    expect(await ruleIdsFor({ "src/pages/index.tsx": src })).toEqual(["AUTH-007"]);
  });

  it("does not flag pages with getServerSideProps", async () => {
    const src = CLIENT.replace('"use client";\n', "") + "export async function getServerSideProps() { return { props: {} }; }\n";
    expect(await ruleIdsFor({ "src/pages/index.tsx": src })).toEqual([]);
  });

  it("flags Vite client sources", async () => {
    const src = `import { createClient } from "@supabase/supabase-js";
export const sb = createClient(import.meta.env.VITE_URL, import.meta.env.SERVICE_ROLE_KEY);
`;
    expect(await ruleIdsFor({ "vite.config.ts": "export default {}", "src/lib/sb.ts": src })).toEqual(["AUTH-007"]);
  });

  it("flags service role keys exposed via public env prefixes anywhere", async () => {
    const src = `export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n`;
    expect(await ruleIdsFor({ "lib/x.ts": src })).toEqual(["AUTH-007"]);
  });

  it("does not flag server route handlers", async () => {
    const src = `import { createClient } from "@supabase/supabase-js";
import { getUser } from "@/lib/auth";
const admin = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export async function GET() { const u = await getUser(); return Response.json({ u, a: !!admin }); }
`;
    expect(await ruleIdsFor({ "app/api/x/route.ts": src })).toEqual([]);
  });

  it("does not flag Vite server directories", async () => {
    const src = `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n`;
    expect(await ruleIdsFor({ "vite.config.ts": "export default {}", "server/admin.ts": src })).toEqual([]);
  });
});
