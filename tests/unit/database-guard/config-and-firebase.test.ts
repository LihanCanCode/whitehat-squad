import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { parseToml } from "../../../src/agents/database-guard/toml.js";
import { memContext } from "../../helpers/memfs.js";

const scan = (files: Record<string, string>) => agent.run(memContext(files));
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

describe("parseToml", () => {
  it("reads sections, dotted and quoted names, scalars and tolerates junk", () => {
    const t = parseToml(`# c
project_id = "x" # trailing
[auth]
enable_anonymous_sign_ins = true
port = 54321
[functions.my-fn]
verify_jwt = false
[storage.buckets."my bucket"]
public = true
files = [
  "a",
  "b"
]
[[array]]
x = 'lit'
broken line here
= nothing
`);
    expect(t.get("")?.values["project_id"]).toBe("x");
    expect(t.get("auth")?.values["enable_anonymous_sign_ins"]).toBe(true);
    expect(t.get("auth")?.values["port"]).toBe(54321);
    expect(t.get("functions.my-fn")?.values["verify_jwt"]).toBe(false);
    expect(t.get("functions.my-fn")?.lines["verify_jwt"]).toBe(7);
    expect(t.get("storage.buckets.my bucket")?.values["public"]).toBe(true);
    expect(t.get("array")?.values["x"]).toBe("lit");
  });
  it("never throws on garbage", () => {
    expect(() => parseToml('[[[\n"unterminated\n=\n[a\n')).not.toThrow();
  });
});

describe("DB-020 edge functions with verify_jwt = false", () => {
  const cfg = "[functions.hook]\nverify_jwt = false\n";
  it("flags a function with no auth of its own", async () => {
    const f = await scan({
      "supabase/config.toml": cfg,
      "supabase/functions/hook/index.ts": "const db = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\nDeno.serve(async (req) => { const b = await req.json(); await db.from('t').insert(b); return new Response('ok'); });",
    });
    expect(ids(f)).toEqual(["DB-020"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.evidence[0]!.file).toBe("supabase/config.toml");
    expect(f[0]!.evidence[0]!.line).toBe(2);
    expect(f[0]!.fix.config).toContain("verify_jwt");
    expect(f[0]!.fix.references.length).toBeGreaterThan(0);
  });
  it.each([
    "const { data } = await supabase.auth.getUser(token);",
    "const c = await supabase.auth.getClaims(token);",
    "await jwtVerify(token, key);",
    "const e = stripe.webhooks.constructEvent(body, sig, secret);",
    "const e = await stripe.webhooks.constructEventAsync(body, sig, secret);",
    "if (!timingSafeEqual(a, b)) throw 1;",
    "await crypto.subtle.verify('HMAC', k, sig, data);",
    "if (req.headers.get('Authorization') !== `Bearer ${Deno.env.get('CRON_SECRET')}`) return new Response('no', { status: 401 });",
  ])("is quiet when the function checks auth itself: %s", async (code) => {
    const f = await scan({ "supabase/config.toml": cfg, "supabase/functions/hook/index.ts": `Deno.serve(async (req) => { ${code} return new Response('ok'); });` });
    expect(f).toEqual([]);
  });
  it("is quiet for verify_jwt = true, a missing function, and a shared auth helper", async () => {
    expect(await scan({ "supabase/config.toml": "[functions.hook]\nverify_jwt = true\n", "supabase/functions/hook/index.ts": "x" })).toEqual([]);
    expect(await scan({ "supabase/config.toml": cfg })).toEqual([]);
    const f = await scan({
      "supabase/config.toml": cfg,
      "supabase/functions/hook/index.ts": "import { requireUser } from '../_shared/auth.ts'; Deno.serve(async (req) => { await requireUser(req); });",
      "supabase/functions/_shared/auth.ts": "export async function requireUser(r){ return supabase.auth.getUser(r.headers.get('Authorization')); }",
    });
    expect(f).toEqual([]);
  });
});

describe("DB-021 anonymous sign-ins with to authenticated policies", () => {
  const sql = (cond: string, cols = "body text") => `create table public.posts (id int, ${cols}); alter table public.posts enable row level security;
create policy "all" on public.posts for select to authenticated using (${cond});`;
  it("flags config-enabled anonymous sign-ins", async () => {
    const f = await scan({ "supabase/config.toml": "[auth]\nenable_anonymous_sign_ins = true\n", "supabase/m.sql": sql("true") });
    const hit = f.find((x) => x.ruleId === "DB-021")!;
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("high");
    expect(hit.fix.sql).toContain("is_anonymous");
  });
  it("flags signInAnonymously( in app code", async () => {
    const f = await scan({ "src/app.ts": "await supabase.auth.signInAnonymously();", "supabase/m.sql": sql("true") });
    expect(ids(f)).toContain("DB-021");
  });
  it("is quiet with an is_anonymous check, without anonymous sign-ins, or for own-row policies", async () => {
    const guarded = await scan({ "supabase/config.toml": "[auth]\nenable_anonymous_sign_ins = true\n", "supabase/m.sql": sql("(auth.jwt() ->> 'is_anonymous')::boolean is false") });
    expect(ids(guarded)).not.toContain("DB-021");
    const off = await scan({ "supabase/config.toml": "[auth]\nenable_anonymous_sign_ins = false\n", "supabase/m.sql": sql("true") });
    expect(ids(off)).not.toContain("DB-021");
    const own = await scan({ "supabase/config.toml": "[auth]\nenable_anonymous_sign_ins = true\n", "supabase/m.sql": sql("(select auth.uid()) = user_id", "user_id uuid") });
    expect(ids(own)).not.toContain("DB-021");
  });
});

describe("config.toml public buckets (DB-007)", () => {
  it("flags [storage.buckets.X] public = true once, with a config fix", async () => {
    const f = await scan({ "supabase/config.toml": "[storage.buckets.avatars]\npublic = true\n" });
    expect(ids(f)).toEqual(["DB-007"]);
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.evidence[0]!.file).toBe("supabase/config.toml");
    expect(f[0]!.fix.config).toContain("public = false");
  });
  it("does not double report a bucket also declared in SQL, nor private ones", async () => {
    const f = await scan({
      "supabase/config.toml": "[storage.buckets.avatars]\npublic = true\n[storage.buckets.docs]\npublic = false\n",
      "supabase/m.sql": "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);",
    });
    expect(ids(f)).toEqual(["DB-007"]);
  });
});

describe("DB-022 Firebase rules that only require sign-in", () => {
  it("flags a wildcard Firestore match with only request.auth != null", async () => {
    const f = await scan({
      "firestore.rules": "service cloud.firestore {\n match /databases/{database}/documents {\n  match /{document=**} {\n   allow read, write: if request.auth != null;\n  }\n }\n}",
    });
    expect(ids(f)).toEqual(["DB-022"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.evidence[0]!.line).toBe(4);
    expect(f[0]!.fix.config).toContain("request.auth.uid");
  });
  it("flags a collection wildcard and storage rules", async () => {
    const a = await scan({ "firestore.rules": "service cloud.firestore { match /databases/{d}/documents { match /{collection}/{doc} { allow read: if request.auth != null; } } }" });
    expect(ids(a)).toEqual(["DB-022"]);
    const b = await scan({ "storage.rules": "service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow write: if request.auth != null; } } }" });
    expect(ids(b)).toEqual(["DB-022"]);
  });
  it("is quiet for per-user and fixed paths (control: open rules still DB-010)", async () => {
    const f = await scan({
      "firestore.rules": `service cloud.firestore { match /databases/{d}/documents {
        match /users/{userId}/{document=**} { allow read, write: if request.auth != null && request.auth.uid == userId; }
        match /posts/{id} { allow read: if request.auth != null; }
      } }`,
    });
    expect(f).toEqual([]);
    const open = await scan({ "firestore.rules": "match /{d=**} { allow read: if true; }" });
    expect(ids(open)).toEqual(["DB-010"]);
  });
  it("flags RTDB auth != null at the root or a wildcard, not on a fixed child or uid check", async () => {
    const root = await scan({ "database.rules.json": '{\n "rules": {\n  ".read": "auth != null",\n  ".write": "auth != null"\n }\n}' });
    expect(ids(root)).toEqual(["DB-022", "DB-022"]);
    expect(root[0]!.evidence[0]!.line).toBe(3);
    const wild = await scan({ "database.rules.json": '{ "rules": { "users": { "$uid": { ".read": "auth != null" } } } }' });
    expect(ids(wild)).toEqual(["DB-022"]);
    const quiet = await scan({ "database.rules.json": '{ "rules": { "posts": { ".read": "auth != null" }, "users": { "$uid": { ".read": "auth != null && auth.uid === $uid" } } } }' });
    expect(quiet).toEqual([]);
  });
  it("follows custom rule paths declared in firebase.json", async () => {
    const f = await scan({
      "firebase.json": JSON.stringify({ firestore: { rules: "config/fs.rules" }, storage: [{ rules: "config/st.rules" }], database: { rules: "config/db.json" } }),
      "config/fs.rules": "match /{document=**} { allow read: if request.auth != null; }",
      "config/st.rules": "match /{allPaths=**} { allow read: if request.auth != null; }",
      "config/db.json": '{ "rules": { ".read": "auth != null" } }',
    });
    expect(ids(f)).toEqual(["DB-022", "DB-022", "DB-022"]);
    expect(f.map((x) => x.evidence[0]!.file).sort()).toEqual(["config/db.json", "config/fs.rules", "config/st.rules"]);
  });
  it("does not double scan a custom path that is also a default name", async () => {
    const f = await scan({
      "firebase.json": JSON.stringify({ firestore: { rules: "firestore.rules" } }),
      "firestore.rules": "match /{document=**} { allow read: if request.auth != null; }",
    });
    expect(ids(f)).toEqual(["DB-022"]);
  });
});

// Public-repo study regression: auth lives two imports away from the function.
describe("DB-020 follows shared auth helpers several imports deep", () => {
  it("is quiet when a _shared helper chain authenticates; fires when no file in the chain does", async () => {
    const { agent } = await import("../../../src/agents/database-guard/index.js");
    const { memContext } = await import("../../helpers/memfs.js");
    const files = (authBody: string) => ({
      "supabase/config.toml": '[functions.jobs]\nverify_jwt = false\n',
      "supabase/functions/jobs/index.ts": 'import { requireOrg } from "../_shared/orgAuth.ts";\nDeno.serve(async (req) => { await requireOrg(req); return new Response("ok"); });\n',
      "supabase/functions/_shared/orgAuth.ts": 'import { caller } from "./auth.ts";\nexport async function requireOrg(req: Request) { return caller(req); }\n',
      "supabase/functions/_shared/auth.ts": authBody,
    });
    const run = async (f: Record<string, string>) => (await agent.run(memContext(f))).filter((x) => x.ruleId === "DB-020");
    expect(await run(files('export async function caller(req: Request) { const { data } = await supabase.auth.getUser(req.headers.get("Authorization")!); return data; }\n'))).toEqual([]);
    expect(await run(files("export async function caller(req: Request) { return null; }\n"))).toHaveLength(1);
  });
});
