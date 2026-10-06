import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { fakeHttp, memContext } from "../../helpers/memfs.js";
import type { SafeHttpClient } from "../../../src/core/types.js";

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (role: string) => `eyJ${b64({ alg: "HS256" }).slice(3)}.${b64({ role })}.sig_abc-123`;
const ANON = jwt("anon");
const SB = "https://abcdefghijklmnopqrst.supabase.co";
const SECRET = "secret@victim.com";
const stack = { frameworks: [], backends: ["supabase" as const], routes: [], supabaseUrl: SB, anonKey: ANON };
const src = (code: string) => ({ "src/app.ts": code });

describe("DB-L01 supabase read probe", () => {
  it("reports a readable table with names only", async () => {
    const url = `${SB}/rest/v1/users?select=*&limit=1`;
    const http = fakeHttp({ [url]: { body: JSON.stringify([{ id: 1, email: SECRET }]) } });
    const ctx = memContext(src('const r = await supabase.from("users").select("*")'), { mode: "live", http, stack });
    const f = await agent.run(ctx);
    expect(f.map((x) => x.ruleId)).toEqual(["DB-L01"]);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.evidence[0]!.snippet).toContain("email");
    expect(f[0]!.explanation).toContain("nyone on the internet");
    expect(f[0]!.fix.sql).toContain("ENABLE ROW LEVEL SECURITY");
    const dump = JSON.stringify(f);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(ANON);
    expect(http.calls).toEqual([url]);
  });

  it("sends the anon key as headers", async () => {
    const seen: Record<string, string>[] = [];
    const http: SafeHttpClient = {
      get: async (url, opts) => {
        seen.push(opts?.headers ?? {});
        return { url, status: 401, headers: {}, setCookies: [], body: "" };
      },
      head: async (url) => ({ url, status: 405, headers: {}, setCookies: [], body: "" }),
    };
    await agent.run(memContext(src('sb.from("t")'), { mode: "live", http, stack }));
    expect(seen[0]).toMatchObject({ apikey: ANON, Authorization: `Bearer ${ANON}` });
  });

  it("stays quiet for empty, blocked, malformed and failing responses", async () => {
    const code = 'sb.from("a"); sb.from("b"); sb.from("c"); sb.from("d")';
    const http = fakeHttp({
      [`${SB}/rest/v1/a?select=*&limit=1`]: { body: "[]" },
      [`${SB}/rest/v1/b?select=*&limit=1`]: { status: 401, body: '{"message":"nope"}' },
      [`${SB}/rest/v1/c?select=*&limit=1`]: { body: "<html>" },
    });
    const throwing: SafeHttpClient = {
      ...http,
      get: async (u, o) => {
        if (u.includes("/d?")) throw new Error("boom");
        return http.get(u, o);
      },
    };
    const f = await agent.run(memContext(src(code), { mode: "live", http: throwing, stack }));
    expect(f).toEqual([]);
  });

  it("still reports when the body is truncated invalid JSON", async () => {
    const url = `${SB}/rest/v1/users?select=*&limit=1`;
    const http = fakeHttp({ [url]: { body: `[{"id":1,"email":"${SECRET}` } });
    const f = await agent.run(memContext(src('sb.from("users")'), { mode: "live", http, stack }));
    expect(f).toHaveLength(1);
    expect(JSON.stringify(f)).not.toContain(SECRET);
  });

  it("does not probe in static mode or without a client", async () => {
    const http = fakeHttp({});
    await agent.run(memContext(src('sb.from("users")'), { mode: "static", http, stack }));
    expect(http.calls).toEqual([]);
    expect(await agent.run(memContext(src('sb.from("users")'), { mode: "live", stack }))).toEqual([]);
  });

  it("ignores Array.from and storage.from, validates names and caps at 20", async () => {
    const names = Array.from({ length: 25 }, (_, i) => `t${i}`);
    const code = names.map((n) => `sb.from('${n}')`).join(";") +
      ';Array.from("x");sb.storage.from("bucket");sb.from("bad name!");sb.from("t1")';
    const http = fakeHttp({});
    await agent.run(memContext(src(code), { mode: "live", http, stack }));
    expect(http.calls).toHaveLength(20);
    expect(http.calls.some((c) => c.includes("bucket") || c.includes("bad") || c.includes("/x?"))).toBe(false);
    expect(new Set(http.calls).size).toBe(20);
  });

  it("extracts the project url, anon key and tables from live bundles", async () => {
    const target = new URL("https://app.example.com/");
    const bundle = `const c=createClient("${SB}","${ANON}");const s="${jwt("service_role")}";c.from("orders")`;
    const probe = `${SB}/rest/v1/orders?select=*&limit=1`;
    const http = fakeHttp({
      "https://app.example.com/": { body: '<script src="/a.js"></script>' },
      "https://app.example.com/a.js": { body: bundle },
      [probe]: { body: JSON.stringify([{ total: 5, secretcol: SECRET }]) },
    });
    const f = await agent.run(memContext({}, { mode: "live", http, target }));
    expect(f.map((x) => x.ruleId)).toEqual(["DB-L01"]);
    expect(http.calls).toContain(probe);
    expect(JSON.stringify(f)).not.toContain(SECRET);
  });

  it("rejects non-anon JWTs found in bundles", async () => {
    const target = new URL("https://app.example.com/");
    const http = fakeHttp({
      "https://app.example.com/": { body: '<script src="/a.js"></script>' },
      "https://app.example.com/a.js": { body: `"${SB}" "${jwt("service_role")}" sb.from("orders")` },
    });
    const f = await agent.run(memContext({}, { mode: "live", http, target }));
    expect(f).toEqual([]);
    expect(http.calls.every((c) => !c.includes("/rest/v1/"))).toBe(true);
  });
});

describe("DB-L02 firestore read probe", () => {
  const fsStack = { frameworks: [], backends: ["firebase" as const], routes: [], firebaseProjectId: "demo-proj" };
  const url = "https://firestore.googleapis.com/v1/projects/demo-proj/databases/(default)/documents/orders?pageSize=1";

  it("reports readable collections with field names only", async () => {
    const body = JSON.stringify({
      documents: [{
        name: "projects/demo-proj/databases/(default)/documents/orders/doc1",
        fields: { email: { stringValue: SECRET }, total: { integerValue: "5" } },
      }],
    });
    const http = fakeHttp({ [url]: { body } });
    const ctx = memContext(src('const q = collection(db, "orders");'), { mode: "live", http, stack: fsStack });
    const f = await agent.run(ctx);
    expect(f.map((x) => x.ruleId)).toEqual(["DB-L02"]);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.evidence[0]!.snippet).toContain("email");
    expect(JSON.stringify(f)).not.toContain(SECRET);
    expect(JSON.stringify(f)).not.toContain("doc1");
    expect(http.calls).toEqual([url]);
  });

  it("is quiet on permission denied and empty collections", async () => {
    const http = fakeHttp({ [url]: { status: 403, body: '{"error":{"status":"PERMISSION_DENIED"}}' } });
    const ctx = memContext(src('collection(db, "orders")'), { mode: "live", http, stack: fsStack });
    expect(await agent.run(ctx)).toEqual([]);
    const empty = fakeHttp({ [url]: { body: "{}" } });
    expect(await agent.run(memContext(src('collection(db, "orders")'), { mode: "live", http: empty, stack: fsStack }))).toEqual([]);
  });

  it("picks the project id out of a bundle when the stack lacks one", async () => {
    const target = new URL("https://app.example.com/");
    const http = fakeHttp({
      "https://app.example.com/": { body: '<script src="/a.js"></script>' },
      "https://app.example.com/a.js": { body: 'initializeApp({projectId:"demo-proj"});collection(db,"orders")' },
      [url]: { body: JSON.stringify({ documents: [{ fields: { a: {} } }] }) },
    });
    const f = await agent.run(memContext({}, { mode: "live", http, target }));
    expect(f.map((x) => x.ruleId)).toEqual(["DB-L02"]);
  });
});
