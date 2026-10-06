import { describe, expect, it } from "vitest";
import { express, only, route, scanOne } from "./helpers.js";

describe("INJ-005 SSRF", () => {
  it("flags fetch of a whole tainted URL (high, CWE-918)", async () => {
    const code = route("  const { url } = await req.json();\n  const r = await fetch(url);\n  return Response.json(await r.json());");
    const f = only(await scanOne(code, "app/api/proxy/route.ts"), "INJ-005");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-918" });
    expect(f[0]?.fix.agentPrompt).toContain("app/api/proxy/route.ts");
    expect(f[0]?.fix.references.some((r) => r.includes("Server_Side_Request_Forgery"))).toBe(true);
  });
  it("flags axios/got/ky/undici/http.get variants and axios({ url })", async () => {
    const calls = [
      "axios.get(req.query.u)",
      "axios.post(req.body.target, {})",
      "axios({ url: req.body.u, method: 'get' })",
      "axios.request({ method: 'get', url: req.query.u })",
      "got(req.query.u)",
      "got.get(req.query.u)",
      "ky.get(req.query.u)",
      "undici.request(req.query.u)",
      "https.get(req.query.u, () => {})",
    ];
    for (const c of calls) {
      const code = express(`  await ${c};`, "const axios = require('axios'); const got = require('got'); const ky = require('ky'); const undici = require('undici'); const https = require('https');");
      expect(only(await scanOne(code), "INJ-005"), c).toHaveLength(1);
    }
  });
  it("flags tainted data that controls the host or scheme of a template", async () => {
    for (const t of ["`https://${req.query.host}/api`", "`${req.body.base}/v1/x`", '"http://" + req.query.h + "/x"', "`https://api.${req.query.region}.example.com/x`"]) {
      const code = express(`  await fetch(${t});`);
      expect(only(await scanOne(code), "INJ-005"), t).toHaveLength(1);
    }
  });
  it("flags a url variable built from tainted input", async () => {
    const code = express("  const target = `${req.body.base}/v1`;\n  await fetch(target);");
    expect(only(await scanOne(code), "INJ-005")).toHaveLength(1);
  });
  it("does not flag a fixed origin with tainted path/query; still flags the host-controlled one", async () => {
    const safe = express(
      "  await fetch(`https://api.example.com/users/${req.params.id}`);\n  await fetch(\"https://api.example.com/search?q=\" + req.query.q);\n  await fetch(`${process.env.API_URL}/users/${req.params.id}`);\n  const u = new URL(\"https://api.example.com/x\");\n  u.pathname = req.query.p;\n  await fetch(u);",
    );
    expect(only(await scanOne(safe), "INJ-005")).toEqual([]);
    const control = express("  await fetch(`https://${req.params.id}.example.com/users`);");
    expect(only(await scanOne(control), "INJ-005")).toHaveLength(1);
  });
  it("does not flag a host allowlist or a safe-url helper; still flags without them", async () => {
    const allow = express(
      '  const { url } = req.body;\n  const host = new URL(url).hostname;\n  if (!ALLOWED_HOSTS.includes(host)) return res.sendStatus(400);\n  await fetch(url);',
      'const ALLOWED_HOSTS = ["api.example.com"];',
    );
    expect(only(await scanOne(allow), "INJ-005")).toEqual([]);
    const helper = express("  const { url } = req.body;\n  if (!isSafeUrl(url)) return res.sendStatus(400);\n  await fetch(url);");
    expect(only(await scanOne(helper), "INJ-005")).toEqual([]);
    const set = express('  const { url } = req.body;\n  if (!allowedHosts.has(new URL(url).hostname)) return res.sendStatus(400);\n  await fetch(url);');
    expect(only(await scanOne(set), "INJ-005")).toEqual([]);
    const open = express("  const { url } = req.body;\n  await fetch(url);");
    expect(only(await scanOne(open), "INJ-005")).toHaveLength(1);
  });
  it("does not flag client components, relative URLs, or untainted URLs", async () => {
    const client = `"use client";\nexport function A({ id }) {\n  const searchParams = useSearchParams();\n  fetch(searchParams.get("u"));\n}\n`;
    expect(await scanOne(client, "components/a.tsx")).toEqual([]);
    const rel = express("  await fetch(`/api/${req.params.id}`);\n  await fetch(\"https://example.com\");\n  await fetch(new URL(\"/x\", base));");
    expect(only(await scanOne(rel), "INJ-005")).toEqual([]);
  });
  it("does not treat a member .fetch( as the global fetch", async () => {
    const code = express("  await env.ASSETS.fetch(req.body.u);\n  await this.client.fetch(req.body.u);");
    expect(only(await scanOne(code), "INJ-005")).toEqual([]);
  });
});

describe("INJ-006 open redirect", () => {
  const NAV = `import { redirect } from "next/navigation";`;
  it("flags redirect(searchParams.get('next')) (medium, CWE-601)", async () => {
    const code = `${NAV}\nexport async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const next = searchParams.get("next") ?? "/";\n  redirect(next);\n}\n`;
    const f = only(await scanOne(code, "app/auth/callback/route.ts"), "INJ-006");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", cwe: "CWE-601" });
    expect(f[0]?.evidence[0]?.line).toBe(5);
    expect(f[0]?.fix.agentPrompt).toContain("app/auth/callback/route.ts");
    expect(f[0]?.fix.references.some((r) => r.includes("Unvalidated_Redirects"))).toBe(true);
  });
  it("flags the Supabase callback template ${origin}${next} and NextResponse.redirect", async () => {
    const code = `import { NextResponse } from "next/server";\nexport async function GET(request: Request) {\n  const { searchParams, origin } = new URL(request.url);\n  const next = searchParams.get("next") ?? "/";\n  return NextResponse.redirect(\`\${origin}\${next}\`);\n}\n`;
    const f = only(await scanOne(code, "app/auth/callback/route.ts"), "INJ-006");
    expect(f).toHaveLength(1);
    expect(f[0]?.explanation).toContain("@");
  });
  it("flags res.redirect (with status), Response.redirect, new URL(next, base) and a leading-slash-only template", async () => {
    for (const body of [
      "  res.redirect(req.query.returnTo);",
      "  res.redirect(302, req.query.redirect_to);",
      "  return Response.redirect(req.query.url);",
      "  return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('next'), req.url));",
      "  res.redirect(`/${req.query.next}`);",
    ]) {
      expect(only(await scanOne(express(body)), "INJ-006"), body).toHaveLength(1);
    }
  });
  it("flags client navigation from search params: router.push and window.location", async () => {
    const code = `"use client";\nimport { useRouter, useSearchParams } from "next/navigation";\nexport function Login() {\n  const router = useRouter();\n  const sp = useSearchParams();\n  const next = sp.get("redirect");\n  const done = () => router.push(next);\n  const hard = () => { window.location.href = next; };\n  return null;\n}\n`;
    expect(only(await scanOne(code, "components/login.tsx"), "INJ-006")).toHaveLength(2);
    const loc = `export function f() {\n  const to = new URLSearchParams(window.location.search).get("to");\n  location.assign(to);\n}\n`;
    expect(only(await scanOne(loc, "src/f.ts"), "INJ-006")).toHaveLength(1);
  });
  it("does not flag fixed paths, templates with a path segment first, or next-auth redirect callbacks", async () => {
    const safe = express(
      "  res.redirect(`/dashboard/${req.params.id}`);\n  res.redirect(`/login?next=${req.query.next}`);\n  res.redirect(`${BASE}/done/${req.query.id}`);\n  res.redirect(`https://app.example.com/${req.query.p}`);\n  res.redirect(\"/home\");",
      'const BASE = "https://x.com";',
    );
    expect(only(await scanOne(safe), "INJ-006")).toEqual([]);
    const cb = `export const callbacks = {\n  async redirect({ url, baseUrl }) {\n    if (url.startsWith("/")) return \`\${baseUrl}\${url}\`;\n    return baseUrl;\n  },\n};\n`;
    expect(only(await scanOne(cb, "auth.ts"), "INJ-006")).toEqual([]);
  });
  it("does not flag a relative-path check that also rejects //; still flags the check that does not", async () => {
    const guarded = express('  const next = req.query.next;\n  if (!next.startsWith("/") || next.startsWith("//")) return res.sendStatus(400);\n  res.redirect(next);');
    expect(only(await scanOne(guarded), "INJ-006")).toEqual([]);
    const guarded2 = express('  const next = req.query.next;\n  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/";\n  res.redirect(safe);');
    expect(only(await scanOne(guarded2), "INJ-006")).toEqual([]);
    const weak = express('  const next = req.query.next;\n  if (!next.startsWith("/")) return res.sendStatus(400);\n  res.redirect(next);');
    expect(only(await scanOne(weak), "INJ-006")).toHaveLength(1);
  });
  it("does not flag allowlists, same-origin checks or safe-redirect helpers", async () => {
    const allow = express('  const next = req.query.next;\n  if (!ALLOWED_REDIRECTS.includes(next)) return res.sendStatus(400);\n  res.redirect(next);', "const ALLOWED_REDIRECTS = [\"/a\"];");
    expect(only(await scanOne(allow), "INJ-006")).toEqual([]);
    const origin = express("  const u = new URL(req.query.next, base);\n  if (u.origin !== base.origin) return res.sendStatus(400);\n  res.redirect(u.toString());", 'const base = new URL("https://app.example.com");');
    expect(only(await scanOne(origin), "INJ-006")).toEqual([]);
    const helper = express("  res.redirect(getSafeRedirect(req.query.next));");
    expect(only(await scanOne(helper), "INJ-006")).toEqual([]);
    const control = express("  res.redirect(req.query.next);");
    expect(only(await scanOne(control), "INJ-006")).toHaveLength(1);
  });
  it("does not flag redirects of untainted values", async () => {
    const code = `${NAV}\nexport async function GET(request: Request) {\n  const { data } = await supabase.auth.signInWithOAuth({ provider: "github" });\n  redirect(data.url);\n}\n`;
    expect(only(await scanOne(code, "app/auth/route.ts"), "INJ-006")).toEqual([]);
  });
});

describe("INJ-006 real-corpus regressions", () => {
  it("does not flag a same-origin URL clone with a literal pathname; still flags a tainted URL object", async () => {
    const safe = `import { NextResponse } from "next/server";\nexport async function middleware(request) {\n  const url = request.nextUrl.clone();\n  url.pathname = "/auth/login";\n  return NextResponse.redirect(url);\n}\n`;
    expect(only(await scanOne(safe, "middleware.ts"), "INJ-006")).toEqual([]);
    const bad = `import { NextResponse } from "next/server";\nexport async function GET(request) {\n  const url = new URL(request.nextUrl.searchParams.get("to"));\n  return NextResponse.redirect(url);\n}\n`;
    expect(only(await scanOne(bad, "app/r/route.ts"), "INJ-006")).toHaveLength(1);
  });
  it("does not flag new URL('/literal', req.url) held in a variable; still flags new URL(next, req.url)", async () => {
    const safe = `export async function middleware(req) {\n  const u = new URL("/onboarding", req.url);\n  return NextResponse.redirect(u);\n}\n`;
    expect(only(await scanOne(safe, "proxy.ts"), "INJ-006")).toEqual([]);
    const bad = `export async function GET(req) {\n  const u = new URL(req.nextUrl.searchParams.get("next"), req.url);\n  return NextResponse.redirect(u);\n}\n`;
    expect(only(await scanOne(bad, "app/r/route.ts"), "INJ-006")).toHaveLength(1);
  });
  it("does not flag a locale route segment after a leading slash; still flags a query value there", async () => {
    const safe = `"use client";\nimport { useParams, useRouter } from "next/navigation";\nexport function A() {\n  const params = useParams();\n  const router = useRouter();\n  return () => router.push(\`/\${params.locale}/dashboard\`);\n}\n`;
    expect(only(await scanOne(safe, "components/a.tsx"), "INJ-006")).toEqual([]);
    const bad = `"use client";\nimport { useSearchParams, useRouter } from "next/navigation";\nexport function A() {\n  const sp = useSearchParams();\n  const router = useRouter();\n  return () => router.push(\`/\${sp.get("to")}\`);\n}\n`;
    expect(only(await scanOne(bad, "components/a.tsx"), "INJ-006")).toHaveLength(1);
  });
  it("does not flag a server action's own parameter; still flags searchParams in a page", async () => {
    const safe = `"use server";\nimport { redirect } from "next/navigation";\nexport async function redirectToPath(path: string) {\n  return redirect(path);\n}\n`;
    expect(only(await scanOne(safe, "utils/server.ts"), "INJ-006")).toEqual([]);
    const bad = `import { redirect } from "next/navigation";\nexport default function Page({ searchParams }) {\n  redirect(searchParams.next);\n}\n`;
    expect(only(await scanOne(bad, "app/login/page.tsx"), "INJ-006")).toHaveLength(1);
  });
  it("flags origin + next (auth callback shape)", async () => {
    const code = `export async function GET(request: Request) {\n  const requestUrl = new URL(request.url);\n  const next = requestUrl.searchParams.get("next");\n  if (next) {\n    return NextResponse.redirect(requestUrl.origin + next);\n  }\n}\n`;
    expect(only(await scanOne(code, "app/auth/callback/route.ts"), "INJ-006")).toHaveLength(1);
  });
});

describe("INJ-006 locale alias regression", () => {
  it("does not flag `const locale = (params.locale as string) || 'en'` after a leading slash; still flags an unrelated alias", async () => {
    const mk = (decl: string): string =>
      `"use client";\nimport { useParams, useRouter } from "next/navigation";\nexport default function P() {\n  const params = useParams();\n  const router = useRouter();\n  ${decl}\n  return () => router.push(\`/\${dest}/x\`);\n}\n`;
    expect(only(await scanOne(mk("const dest = (params.locale as string) || 'en';"), "app/p/page.tsx"), "INJ-006")).toEqual([]);
    expect(only(await scanOne(mk("const dest = params.target as string;"), "app/p/page.tsx"), "INJ-006")).toEqual([]);
    expect(only(await scanOne(mk("const dest = new URLSearchParams(window.location.search).get('to');"), "app/p/page.tsx"), "INJ-006")).toHaveLength(1);
  });
});

// Public-repo study regression: client-side router navigation cannot leave the app's origin.
describe("INJ-006: React Router / TanStack navigate() is not an open redirect", () => {
  const page = (body: string) =>
    `"use client";\nimport { useNavigate, useSearchParams, useParams } from "react-router-dom";\nexport default function P() {\n  const navigate = useNavigate();\n  const [sp] = useSearchParams();\n  const { id } = useParams();\n${body}\n  return null;\n}\n`;
  it("stays quiet on in-app navigate() calls seen in real apps", async () => {
    for (const body of [
      "  navigate(id ? `/boiler-enquiries/${id}` : \"/quotes\");",
      "  navigate({ to: \"/series/$slug\", params: { slug: id } });",
      "  navigate(location.pathname + location.search + location.hash, { replace: true });",
      "  navigate(sp.get(\"next\") ?? \"/\");",
    ]) {
      expect(only(await scanOne(page(body), "src/pages/P.tsx"), "INJ-006"), body).toEqual([]);
    }
  });
  it("control: full-page redirects to a request value still fire", async () => {
    expect(only(await scanOne(page("  window.location.href = sp.get(\"next\") ?? \"/\";"), "src/pages/P.tsx"), "INJ-006")).toHaveLength(1);
    expect(only(await scanOne(page("  router.push(sp.get(\"next\"));"), "src/pages/P.tsx"), "INJ-006")).toHaveLength(1);
  });
});
