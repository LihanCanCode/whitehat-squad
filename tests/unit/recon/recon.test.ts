import { describe, expect, it } from "vitest";
import { agent, profileStack } from "../../../src/agents/recon/index.js";
import { extractBackendHints } from "../../../src/agents/recon/hints.js";
import { routesFromPaths } from "../../../src/agents/recon/routes.js";
import type { FileIndex, SafeHttpClient } from "../../../src/core/types.js";
import { fakeHttp, memContext, memFiles } from "../../helpers/memfs.js";

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ role, iss: "supabase" })}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;
const REF = "abcdefghijklmnopqrst";
const URL_ = `https://${REF}.supabase.co`;
const pkg = (deps: Record<string, string>, dev: Record<string, string> = {}) =>
  JSON.stringify({ dependencies: deps, devDependencies: dev });

describe("static framework detection", () => {
  it("detects next from deps and from config", async () => {
    expect((await profileStack({ files: memFiles({ "package.json": pkg({ next: "14" }) }) })).frameworks).toContain("next");
    expect((await profileStack({ files: memFiles({ "next.config.mjs": "export default {}" }) })).frameworks).toContain("next");
  });
  it("detects vite, react, remix, express", async () => {
    const p = await profileStack({
      files: memFiles({
        "vite.config.ts": "",
        "package.json": pkg({ react: "18", "@remix-run/node": "2", express: "4" }),
      }),
    });
    expect(p.frameworks).toEqual(expect.arrayContaining(["vite", "react", "remix", "express"]));
  });
  it("detects devDependencies too", async () => {
    const p = await profileStack({ files: memFiles({ "package.json": pkg({}, { express: "4" }) }) });
    expect(p.frameworks).toEqual(["express"]);
  });
});

describe("static backend detection", () => {
  it("detects supabase from dep, dir and env name", async () => {
    expect((await profileStack({ files: memFiles({ "package.json": pkg({ "@supabase/supabase-js": "2" }) }) })).backends).toContain("supabase");
    expect((await profileStack({ files: memFiles({ "supabase/config.toml": "" }) })).backends).toContain("supabase");
    expect((await profileStack({ files: memFiles({ ".env.example": "NEXT_PUBLIC_SUPABASE_URL=" }) })).backends).toContain("supabase");
  });
  it("detects firebase from dep, firebase.json, firestore.rules", async () => {
    expect((await profileStack({ files: memFiles({ "package.json": pkg({ firebase: "10" }) }) })).backends).toContain("firebase");
    expect((await profileStack({ files: memFiles({ "firebase.json": "{}" }) })).backends).toContain("firebase");
    expect((await profileStack({ files: memFiles({ "firestore.rules": "" }) })).backends).toContain("firebase");
  });
  it("detects stripe, openai, anthropic from deps and imports", async () => {
    const deps = await profileStack({ files: memFiles({ "package.json": pkg({ stripe: "1", openai: "4", "@anthropic-ai/sdk": "1" }) }) });
    expect(deps.backends).toEqual(expect.arrayContaining(["stripe", "openai", "anthropic"]));
    const imports = await profileStack({
      files: memFiles({
        "src/a.ts": `import Stripe from "stripe"; import OpenAI from 'openai'; import A from "@anthropic-ai/sdk";`,
      }),
    });
    expect(imports.backends).toEqual(expect.arrayContaining(["stripe", "openai", "anthropic"]));
  });
});

describe("keys and ids", () => {
  it("extracts supabase url and anon key from code", async () => {
    const p = await profileStack({
      files: memFiles({ "src/lib/sb.ts": `createClient("${URL_}", "${jwt("anon")}")` }),
    });
    expect(p.supabaseUrl).toBe(URL_);
    expect(p.anonKey).toBe(jwt("anon"));
    expect(p.backends).toContain("supabase");
  });
  it("reads .env and .env.example", async () => {
    const p = await profileStack({ files: memFiles({ ".env": `NEXT_PUBLIC_SUPABASE_URL=${URL_}\nKEY=${jwt("anon")}` }) });
    expect(p.supabaseUrl).toBe(URL_);
    expect(p.anonKey).toBe(jwt("anon"));
  });
  it("never accepts a service_role key as anonKey", async () => {
    const p = await profileStack({
      files: memFiles({ ".env": `SERVICE=${jwt("service_role")}\nANON=${jwt("anon")}` }),
    });
    expect(p.anonKey).toBe(jwt("anon"));
    const only = await profileStack({ files: memFiles({ ".env": `SERVICE=${jwt("service_role")}` }) });
    expect(only.anonKey).toBeUndefined();
  });
  it("ignores malformed JWT-looking strings", () => {
    const h = extractBackendHints("eyJhbGciOiJIUzI1NiJ9.eyJ!!!notbase64.abcdefghijklmnop eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijklmnop");
    expect(h.anonKey).toBeUndefined();
  });
  it("reads firebase projectId from config and .firebaserc", async () => {
    const a = await profileStack({
      files: memFiles({ "src/firebase.ts": `initializeApp({ apiKey: "x", authDomain: "d", projectId: "my-proj-1" })` }),
    });
    expect(a.firebaseProjectId).toBe("my-proj-1");
    expect(a.backends).toContain("firebase");
    const b = await profileStack({ files: memFiles({ ".firebaserc": JSON.stringify({ projects: { default: "rc-proj" } }) }) });
    expect(b.firebaseProjectId).toBe("rc-proj");
  });
  it("does not treat a non-firebase projectId as firebase", async () => {
    const p = await profileStack({ files: memFiles({ "src/x.ts": `const cfg = { projectId: "foo-bar" }` }) });
    expect(p.firebaseProjectId).toBeUndefined();
  });
});

describe("routes", () => {
  it("maps next app router pages and routes", async () => {
    const p = await profileStack({
      files: memFiles({
        "next.config.js": "",
        "app/page.tsx": "",
        "app/dashboard/page.tsx": "",
        "app/(auth)/login/page.jsx": "",
        "app/api/users/[id]/route.ts": "",
        "app/layout.tsx": "",
      }),
    });
    expect(p.routes).toEqual(["/", "/api/users/[id]", "/dashboard", "/login"]);
  });
  it("maps pages router and pages/api, skipping _app", async () => {
    const p = await profileStack({
      files: memFiles({
        "next.config.js": "",
        "src/pages/index.tsx": "",
        "src/pages/about.tsx": "",
        "src/pages/blog/index.tsx": "",
        "src/pages/_app.tsx": "",
        "pages/api/hello.ts": "",
      }),
    });
    expect(p.routes).toEqual(["/", "/about", "/api/hello", "/blog"]);
  });
  it("ignores node_modules and caps at 200", () => {
    const paths = Array.from({ length: 300 }, (_, i) => `app/r${i}/page.tsx`);
    expect(routesFromPaths(paths)).toHaveLength(200);
    expect(routesFromPaths(["node_modules/x/app/page.tsx"])).toEqual([]);
  });
  it("produces no routes without next", async () => {
    const p = await profileStack({ files: memFiles({ "pages/foo.tsx": "" }) });
    expect(p.routes).toEqual([]);
  });
});

describe("robustness", () => {
  it("handles empty tree", async () => {
    expect(await profileStack({ files: memFiles({}) })).toEqual({ frameworks: [], backends: [], routes: [] });
  });
  it("survives malformed package.json", async () => {
    const p = await profileStack({ files: memFiles({ "package.json": "{not json", "next.config.js": "" }) });
    expect(p.frameworks).toEqual(["next"]);
  });
  it("survives non-object package.json", async () => {
    const p = await profileStack({ files: memFiles({ "package.json": "[1,2]" }) });
    expect(p.frameworks).toEqual([]);
  });
  it("handles monorepo package.json files", async () => {
    const p = await profileStack({
      files: memFiles({
        "package.json": pkg({}),
        "apps/web/package.json": pkg({ next: "14", stripe: "1" }),
        "apps/web/app/pricing/page.tsx": "",
        "packages/db/package.json": pkg({ "@supabase/supabase-js": "2" }),
        "node_modules/foo/package.json": pkg({ express: "4" }),
      }),
    });
    expect(p.frameworks).toEqual(["next"]);
    expect(p.backends).toEqual(expect.arrayContaining(["supabase", "stripe"]));
    expect(p.routes).toEqual(["/pricing"]);
  });
  it("returns a partial profile when the file index throws", async () => {
    const files: FileIndex = {
      paths: ["package.json", "next.config.js"],
      read: async () => { throw new Error("disk"); },
      isIgnored: () => false,
    };
    const p = await profileStack({ files });
    expect(p.frameworks).toContain("next");
  });
  it("returns an empty profile when paths itself explodes", async () => {
    const files = { get paths(): string[] { throw new Error("boom"); }, read: async () => null, isIgnored: () => false } as unknown as FileIndex;
    expect(await profileStack({ files })).toEqual({ frameworks: [], backends: [], routes: [] });
  });
});

describe("live detection", () => {
  const target = new URL("https://app.example.com/");
  const html = (extra = "") =>
    `<html><script src="/assets/index-abc.js"></script><script src="https://cdn.evil.com/x.js"></script>${extra}</html>`;

  it("extracts keys from bundles and merges with static", async () => {
    const http = fakeHttp({
      "https://app.example.com/": { body: html() },
      "https://app.example.com/assets/index-abc.js": { body: `a("${URL_}","${jwt("anon")}")` },
    });
    const p = await profileStack({ files: memFiles({}), target, http });
    expect(p.frameworks).toContain("vite");
    expect(p.supabaseUrl).toBe(URL_);
    expect(p.anonKey).toBe(jwt("anon"));
    expect(p.backends).toContain("supabase");
    expect(http.calls).not.toContain("https://cdn.evil.com/x.js");
  });
  it("prefers static values over live", async () => {
    const http = fakeHttp({
      "https://app.example.com/": { body: html() },
      "https://app.example.com/assets/index-abc.js": { body: `"https://zzzzzzzzzzzzzzzzzzzz.supabase.co"` },
    });
    const p = await profileStack({ files: memFiles({ ".env": `U=${URL_}` }), target, http });
    expect(p.supabaseUrl).toBe(URL_);
  });
  it("detects next, remix, lovable, stripe, firebase hints", async () => {
    const next = fakeHttp({ "https://app.example.com/": { body: `<script id="__NEXT_DATA__"></script><link href="/_next/static/a.css">` } });
    expect((await profileStack({ files: memFiles({}), target, http: next })).frameworks).toContain("next");
    const remix = fakeHttp({ "https://app.example.com/": { body: `<script>window.__remixContext = {}</script>` } });
    expect((await profileStack({ files: memFiles({}), target, http: remix })).frameworks).toContain("remix");
    const lov = fakeHttp({ "https://app.example.com/": { body: `<meta name="x" content="lovable-tagger">` } });
    expect((await profileStack({ files: memFiles({}), target, http: lov })).frameworks).toEqual(expect.arrayContaining(["vite", "react"]));
    const mix = fakeHttp({
      "https://app.example.com/": { body: `<script src="https://app.example.com/m.js"></script><script src="https://js.stripe.com/v3"></script>` },
      "https://app.example.com/m.js": { body: `initializeApp({authDomain:"x",projectId:"live-proj"})` },
    });
    const p = await profileStack({ files: memFiles({}), target, http: mix });
    expect(p.firebaseProjectId).toBe("live-proj");
    expect(p.backends).toEqual(expect.arrayContaining(["firebase"]));
  });
  it("caps requests at 11", async () => {
    const scripts = Array.from({ length: 30 }, (_, i) => `<script src="/s${i}.js"></script>`).join("");
    const http = fakeHttp({ "https://app.example.com/": { body: scripts } });
    await profileStack({ files: memFiles({}), target, http });
    expect(http.calls.length).toBe(11);
  });
  it("swallows http errors", async () => {
    const http: SafeHttpClient = {
      get: async () => { throw new Error("net down"); },
      head: async () => { throw new Error("net down"); },
    };
    const p = await profileStack({ files: memFiles({ "next.config.js": "" }), target, http });
    expect(p.frameworks).toEqual(["next"]);
  });
  it("tolerates a failing script fetch and 404 landing page", async () => {
    let n = 0;
    const flaky: SafeHttpClient = {
      get: async (url) => {
        if (n++ === 0) return { url, status: 200, headers: {}, setCookies: [], body: `<script src="/a.js"></script>__NEXT_DATA__` };
        throw new Error("x");
      },
      head: async () => { throw new Error("x"); },
    };
    expect((await profileStack({ files: memFiles({}), target, http: flaky })).frameworks).toContain("next");
    const notFound = fakeHttp({});
    expect((await profileStack({ files: memFiles({}), target, http: notFound })).frameworks).toEqual([]);
  });
});

describe("agent", () => {
  it("has the right identity and no findings in static mode", async () => {
    expect(agent.id).toBe("recon");
    expect(await agent.run(memContext({}, { stack: { frameworks: [], backends: ["supabase"], supabaseUrl: URL_, routes: [] } }))).toEqual([]);
  });
  it("emits RECON-L01 info for a supabase project in live mode", async () => {
    const ctx = memContext({}, {
      mode: "live", target: new URL("https://app.example.com/"),
      stack: { frameworks: [], backends: ["supabase"], supabaseUrl: URL_, anonKey: jwt("anon"), routes: [] },
    });
    const out = await agent.run(ctx);
    expect(out).toHaveLength(1);
    const f = out[0]!;
    expect(f.ruleId).toBe("RECON-L01");
    expect(f.severity).toBe("info");
    expect(f.title).toContain(REF);
    expect(f.fix.agentPrompt).toContain("whsquad scan");
    expect(f.fix.agentPrompt).toContain("RLS");
    expect(JSON.stringify(f)).not.toContain(jwt("anon"));
  });
  it("emits for firebase and stays silent with no backend", async () => {
    const target = new URL("https://app.example.com/");
    const fb = await agent.run(memContext({}, { mode: "live", target, stack: { frameworks: [], backends: ["firebase"], firebaseProjectId: "p-1", routes: [] } }));
    expect(fb[0]?.title).toContain("p-1");
    expect(await agent.run(memContext({}, { mode: "live", target }))).toEqual([]);
  });
  it("emits one finding covering both backends and works without a target", async () => {
    const out = await agent.run(memContext({}, {
      mode: "live",
      stack: { frameworks: [], backends: ["supabase", "firebase"], supabaseUrl: URL_, firebaseProjectId: "p-1", routes: [] },
    }));
    expect(out).toHaveLength(1);
    expect(out[0]?.title).toContain("p-1");
    expect(out[0]?.title).toContain(REF);
  });
});
