import { describe, expect, it } from "vitest";
import { agent as databaseGuard } from "../../../src/agents/database-guard/index.js";
import { createSafeHttpClient, isBackendHost, OutOfScopeError } from "../../../src/safety/http-client.js";
import type { PinnedFetch } from "../../../src/safety/http-client.js";
import { fakeHttp, memContext } from "../../helpers/memfs.js";

const origin = new URL("https://app.example.test");
const publicResolver = async () => [{ address: "93.184.216.34", family: 4 }];

function client(extra: { allowBackendHosts?: boolean } = {}) {
  const urls: string[] = [];
  const fetchImpl: PinnedFetch = async (url) => {
    urls.push(url);
    return new Response("[]", { status: 200 });
  };
  return { urls, http: createSafeHttpClient({ origin, rps: 1000, resolver: publicResolver, fetchImpl, ...extra }) };
}

describe("isBackendHost allows only fixed backends", () => {
  it.each(["abcdefghijklmnop.supabase.co", "xyz12345abc.supabase.co", "firestore.googleapis.com"])("allows %s", (h) => {
    expect(isBackendHost(h)).toBe(true);
  });

  it.each([
    "supabase.co",
    "evil.com",
    "a.supabase.co.evil.com",
    "evil-supabase.co",
    "x.y.supabase.co",
    "short.supabase.co",
    "googleapis.com",
    "storage.googleapis.com",
    "firestore.googleapis.com.evil.com",
    "localhost",
    "169.254.169.254",
  ])("rejects %s", (h) => {
    expect(isBackendHost(h)).toBe(false);
  });
});

describe("client scope with and without backend hosts", () => {
  const supabase = "https://abcdefghijklmnop.supabase.co/rest/v1/notes?select=*&limit=1";

  it("blocks a backend host by default", async () => {
    const { http, urls } = client();
    await expect(http.get(supabase)).rejects.toBeInstanceOf(OutOfScopeError);
    expect(urls).toHaveLength(0);
  });

  it("allows exactly the fixed backends when opted in", async () => {
    const { http, urls } = client({ allowBackendHosts: true });
    await http.get(supabase);
    await http.get("https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/users?pageSize=1");
    expect(urls).toHaveLength(2);
  });

  it("still blocks every other host, plain http to a backend, and credentials in the URL", async () => {
    const { http } = client({ allowBackendHosts: true });
    await expect(http.get("https://evil.com/")).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(http.get("https://a.supabase.co.evil.com/")).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(http.get("http://abcdefghijklmnop.supabase.co/")).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(http.get("https://u:p@abcdefghijklmnop.supabase.co/")).rejects.toBeInstanceOf(OutOfScopeError);
  });

  it("still never resolves a backend host to an internal address", async () => {
    const urls: string[] = [];
    const http = createSafeHttpClient({
      origin,
      rps: 1000,
      allowBackendHosts: true,
      resolver: async () => [{ address: "169.254.169.254", family: 4 }],
      fetchImpl: async (u) => {
        urls.push(u);
        return new Response("x");
      },
    });
    await expect(http.get("https://abcdefghijklmnop.supabase.co/")).rejects.toThrow();
    expect(urls).toHaveLength(0);
  });
});

describe("DatabaseGuard live probes are opt-in", () => {
  const anon = "eyJ" + "hbGciOiJIUzI1NiJ9." + Buffer.from(JSON.stringify({ role: "anon" })).toString("base64url") + ".sig";
  const stack = { frameworks: [], backends: ["supabase" as const], routes: [], supabaseUrl: "https://abcdefghijklmnop.supabase.co", anonKey: anon };
  const page = { "https://app.example.test/": { body: '<script>sb.from("notes").select()</script>' } };

  it("sends no backend request unless probeBackend is set", async () => {
    const http = fakeHttp(page);
    const ctx = { ...memContext({}, { mode: "live", target: new URL("https://app.example.test/"), http, stack }), options: { gitHistory: false, maxRequests: 100 } };
    expect(await databaseGuard.run(ctx)).toEqual([]);
    expect(http.calls.filter((u) => u.includes("supabase.co"))).toHaveLength(0);
  });

  it("probes with GET only, and records names but never row values, when enabled", async () => {
    const http = fakeHttp({
      ...page,
      "https://abcdefghijklmnop.supabase.co/rest/v1/notes?select=*&limit=1": { body: '[{"id":1,"body":"SECRET-ROW-VALUE"}]' },
    });
    const ctx = memContext({}, { mode: "live", target: new URL("https://app.example.test/"), http, stack });
    const findings = await databaseGuard.run(ctx);
    const hit = findings.find((f) => f.ruleId === "DB-L01");
    expect(hit?.severity).toBe("critical");
    expect(JSON.stringify(findings)).not.toContain("SECRET-ROW-VALUE");
    expect(JSON.stringify(findings)).not.toContain(anon);
  });
});
