import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/web-hardener/index.js";
import { fakeHttp, httpResult, memContext } from "../../helpers/memfs.js";
import type { HttpResult, SafeHttpClient } from "../../../src/core/types.js";

const ORIGIN = "https://example.com";
const HOME = `${ORIGIN}/`;

const GOOD_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};
const HTML = '<!doctype html><html><body><script src="/app.js"></script></body></html>';

type Routes = Record<string, Partial<HttpResult>>;

async function runLive(routes: Routes, target = HOME) {
  const http = fakeHttp(routes);
  const ctx = memContext({}, { mode: "live", target: new URL(target), http });
  const findings = await agent.run(ctx);
  return { findings, http, ctx };
}
const rule = <T extends { ruleId: string }>(fs: T[], id: string): T[] => fs.filter((f) => f.ruleId === id);
const goodHome: Routes = { [HOME]: { headers: GOOD_HEADERS, body: HTML } , [`${ORIGIN}/app.js`]: { body: "console.log(1)" } };

describe("well-configured site", () => {
  it("produces zero findings, <=20 requests, same origin only", async () => {
    const { findings, http } = await runLive(goodHome);
    expect(findings).toEqual([]);
    expect(http.calls.length).toBeLessThanOrEqual(20);
    expect(http.calls.every((u) => new URL(u).origin === ORIGIN)).toBe(true);
  });
  it("stays within 20 requests even with many scripts and maps", async () => {
    const scripts = Array.from({ length: 15 }, (_, i) => `<script src="/s${i}.js"></script>`).join("");
    const routes: Routes = { [HOME]: { headers: GOOD_HEADERS, body: scripts } };
    for (let i = 0; i < 15; i++) {
      routes[`${ORIGIN}/s${i}.js`] = { body: `x\n//# sourceMappingURL=s${i}.js.map` };
      routes[`${ORIGIN}/s${i}.js.map`] = { body: '{"version":3,"sourcesContent":["a"]}' };
    }
    const { http } = await runLive(routes);
    expect(http.calls.length).toBeLessThanOrEqual(20);
  });
  it("skips header checks when the landing page errors", async () => {
    const { findings } = await runLive({ [HOME]: { status: 500 } });
    expect(findings).toEqual([]);
  });
});

describe("WEB-L01..L06 headers", () => {
  it("reports each missing header with fix config", async () => {
    const { findings } = await runLive({ [HOME]: { body: "<html></html>" } });
    for (const id of ["WEB-L01", "WEB-L02", "WEB-L03", "WEB-L04", "WEB-L05", "WEB-L06"]) {
      const f = rule(findings, id);
      expect(f, id).toHaveLength(1);
      expect(["low", "medium"]).toContain(f[0]?.severity);
      expect(f[0]?.fix.config).toContain("headers()");
      expect(f[0]?.fix.config).toContain("_headers");
      expect(f[0]?.fix.agentPrompt.length).toBeGreaterThan(20);
      expect(f[0]?.fix.references.length).toBeGreaterThan(0);
      expect(f[0]?.evidence[0]?.url).toBe(HOME);
    }
  });
  it("does not require HSTS on http targets", async () => {
    const url = "http://example.com/";
    const { findings } = await runLive({ [url]: { headers: GOOD_HEADERS, body: "" } }, url);
    expect(rule(findings, "WEB-L02")).toHaveLength(0);
  });
  it("accepts X-Frame-Options instead of frame-ancestors", async () => {
    const headers = { ...GOOD_HEADERS, "content-security-policy": "default-src 'self'", "X-Frame-Options": "DENY" };
    const { findings } = await runLive({ [HOME]: { headers, body: "" } });
    expect(rule(findings, "WEB-L03")).toHaveLength(0);
  });
  it("treats unsafe-inline / unsafe-eval / wildcard script-src as weak (low)", async () => {
    for (const csp of [
      "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
      "script-src 'self' 'unsafe-eval'; frame-ancestors 'none'",
      "script-src *; frame-ancestors 'none'",
    ]) {
      const { findings } = await runLive({ [HOME]: { headers: { ...GOOD_HEADERS, "content-security-policy": csp }, body: "" } });
      const f = rule(findings, "WEB-L01");
      expect(f, csp).toHaveLength(1);
      expect(f[0]?.severity).toBe("low");
    }
  });
  it("allows unsafe-inline when a nonce is present", async () => {
    const csp = "script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'";
    const { findings } = await runLive({ [HOME]: { headers: { ...GOOD_HEADERS, "content-security-policy": csp }, body: "" } });
    expect(rule(findings, "WEB-L01")).toHaveLength(0);
  });
  it("flags a short HSTS max-age", async () => {
    const headers = { ...GOOD_HEADERS, "strict-transport-security": "max-age=300" };
    const { findings } = await runLive({ [HOME]: { headers, body: "" } });
    expect(rule(findings, "WEB-L02")).toHaveLength(1);
  });
  it("flags nosniff set to the wrong value", async () => {
    const headers = { ...GOOD_HEADERS, "x-content-type-options": "other" };
    const { findings } = await runLive({ [HOME]: { headers, body: "" } });
    expect(rule(findings, "WEB-L04")).toHaveLength(1);
  });
});

describe("WEB-L07 reflected-origin CORS", () => {
  function corsClient(reflect: boolean, credentials: string): SafeHttpClient & { calls: string[] } {
    const calls: string[] = [];
    const get = async (url: string, opts?: { headers?: Record<string, string> }) => {
      calls.push(url);
      const origin = opts?.headers?.["Origin"];
      const headers: Record<string, string> = { ...GOOD_HEADERS };
      if (origin && reflect) {
        headers["access-control-allow-origin"] = origin;
        headers["access-control-allow-credentials"] = credentials;
      }
      return httpResult({ url, headers, body: url === HOME ? "" : "" , status: url === HOME ? 200 : 404 });
    };
    return { calls, get, head: get };
  }
  const run = async (http: SafeHttpClient) =>
    agent.run(memContext({}, { mode: "live", target: new URL(HOME), http }));

  it("flags echoed origin with credentials as high", async () => {
    const f = rule(await run(corsClient(true, "true")), "WEB-L07");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.cwe).toBe("CWE-942");
  });
  it("ignores echoed origin without credentials, and non-reflecting servers", async () => {
    expect(rule(await run(corsClient(true, "false")), "WEB-L07")).toHaveLength(0);
    expect(rule(await run(corsClient(false, "true")), "WEB-L07")).toHaveLength(0);
  });
});

describe("WEB-L08 cookies", () => {
  it("escalates session cookies missing flags to medium without leaking values", async () => {
    const { findings } = await runLive({
      [HOME]: { headers: GOOD_HEADERS, body: "", setCookies: ["session_id=SUPERSECRETVALUE; Path=/"] },
    });
    const f = rule(findings, "WEB-L08");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(JSON.stringify(f[0])).not.toContain("SUPERSECRETVALUE");
    expect(f[0]?.evidence[0]?.snippet).toContain("session_id");
    expect(f[0]?.evidence[0]?.snippet).toMatch(/Secure/);
  });
  it("uses low severity for non-session cookies", async () => {
    const { findings } = await runLive({
      [HOME]: { headers: GOOD_HEADERS, body: "", setCookies: ["theme=dark; Path=/"] },
    });
    expect(rule(findings, "WEB-L08")[0]?.severity).toBe("low");
  });
  it("accepts fully flagged cookies and csrf cookies readable by JS", async () => {
    const { findings } = await runLive({
      [HOME]: {
        headers: GOOD_HEADERS,
        body: "",
        setCookies: ["sid=abc; Secure; HttpOnly; SameSite=Lax", "XSRF-TOKEN=z; Secure; SameSite=Strict"],
      },
    });
    expect(rule(findings, "WEB-L08")).toHaveLength(0);
  });
});

describe("WEB-L09 source maps", () => {
  const withMap = (mapRes: Partial<HttpResult>): Routes => ({
    ...goodHome,
    [`${ORIGIN}/app.js`]: { body: "var a=1;\n//# sourceMappingURL=app.js.map\n" },
    [`${ORIGIN}/app.js.map`]: mapRes,
  });
  it("reports reachable maps with sourcesContent", async () => {
    const { findings } = await runLive(withMap({ body: '{"version":3,"sources":["a.ts"],"sourcesContent":["secret code"]}' }));
    const f = rule(findings, "WEB-L09");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.evidence[0]?.url).toBe(`${ORIGIN}/app.js.map`);
    expect(JSON.stringify(f[0])).not.toContain("secret code");
  });
  it("ignores 404 maps, maps without sourcesContent, cross-origin and data: maps", async () => {
    expect(rule((await runLive(withMap({ status: 404 }))).findings, "WEB-L09")).toHaveLength(0);
    expect(rule((await runLive(withMap({ body: '{"version":3}' }))).findings, "WEB-L09")).toHaveLength(0);
    const cross: Routes = { ...goodHome, [`${ORIGIN}/app.js`]: { body: "x\n//# sourceMappingURL=https://cdn.other.com/a.map" } };
    const r = await runLive(cross);
    expect(rule(r.findings, "WEB-L09")).toHaveLength(0);
    expect(r.http.calls.some((u) => u.includes("other.com"))).toBe(false);
    const data: Routes = { ...goodHome, [`${ORIGIN}/app.js`]: { body: "x\n//# sourceMappingURL=data:application/json;base64,AAAA" } };
    expect(rule((await runLive(data)).findings, "WEB-L09")).toHaveLength(0);
  });
});

describe("WEB-L10 exposed files", () => {
  it("flags /.git/HEAD as high", async () => {
    const { findings } = await runLive({ ...goodHome, [`${ORIGIN}/.git/HEAD`]: { body: "ref: refs/heads/main\n" } });
    expect(rule(findings, "WEB-L10")[0]?.severity).toBe("high");
  });
  it("flags /.env with secrets as critical, registers secrets, never prints values", async () => {
    const body = "DATABASE_URL=postgres://u:hunter2hunter2@db/x\nSTRIPE_SECRET_KEY=\"sk_live_abcdef123456\"\n# c\nPORT=3000\n";
    const { findings, ctx } = await runLive({ ...goodHome, [`${ORIGIN}/.env`]: { body } });
    const f = rule(findings, "WEB-L10").find((x) => x.evidence[0]?.url === `${ORIGIN}/.env`);
    expect(f?.severity).toBe("critical");
    const dump = JSON.stringify(f);
    expect(dump).not.toContain("hunter2");
    expect(dump).not.toContain("sk_live_abcdef123456");
    expect(ctx.secrets.has("sk_live_abcdef123456")).toBe(true);
    expect(ctx.secrets.has("postgres://u:hunter2hunter2@db/x")).toBe(true);
  });
  it("rates a non-secret .env.local as high", async () => {
    const { findings } = await runLive({ ...goodHome, [`${ORIGIN}/.env.local`]: { body: "PORT=3000\nNODE_ENV=production\n" } });
    expect(rule(findings, "WEB-L10")[0]?.severity).toBe("high");
  });
  it("flags .DS_Store, wp-config backup and phpinfo", async () => {
    const { findings } = await runLive({
      ...goodHome,
      [`${ORIGIN}/.DS_Store`]: { body: "\u0000\u0000\u0000\u0001Bud1\u0000\u0000" },
      [`${ORIGIN}/wp-config.php.bak`]: { body: "<?php\ndefine('DB_NAME','x');\ndefine('DB_PASSWORD','pw-very-secret');" },
      [`${ORIGIN}/phpinfo.php`]: { body: "<html><title>phpinfo()</title>PHP Version 8.1</html>" },
    });
    const urls = rule(findings, "WEB-L10").map((f) => f.evidence[0]?.url);
    expect(urls).toEqual(expect.arrayContaining([`${ORIGIN}/.DS_Store`, `${ORIGIN}/wp-config.php.bak`, `${ORIGIN}/phpinfo.php`]));
    expect(JSON.stringify(findings)).not.toContain("pw-very-secret");
  });
  it("is not fooled by an SPA catch-all returning index.html with 200", async () => {
    const spa: Routes = { [HOME]: { headers: GOOD_HEADERS, body: HTML }, [`${ORIGIN}/app.js`]: { body: "1" } };
    const catchAll = { status: 200, headers: { "content-type": "text/html" }, body: HTML };
    for (const p of ["/.git/HEAD", "/.env", "/.env.local", "/.DS_Store", "/wp-config.php.bak", "/phpinfo.php", "/whsquad-probe-404-check"]) {
      spa[`${ORIGIN}${p}`] = catchAll;
    }
    const { findings } = await runLive(spa);
    expect(findings).toEqual([]);
  });
  it("rejects a .env lookalike that is HTML containing key=value text", async () => {
    const body = "<html><body>\nFOO=bar\n</body></html>";
    const { findings } = await runLive({ ...goodHome, [`${ORIGIN}/.env`]: { body, headers: { "content-type": "text/html" } } });
    expect(rule(findings, "WEB-L10")).toHaveLength(0);
  });
});

describe("WEB-L11 verbose errors", () => {
  const probe = `${ORIGIN}/whsquad-probe-404-check`;
  it("flags stack traces and debug pages", async () => {
    for (const body of [
      "Error: x\n    at Object.<anonymous> (/app/server.js:10:5)",
      "Traceback (most recent call last):\n  File x",
      "<h1>Whoops, looks like something went wrong.</h1>",
      "You're seeing this error because you have DEBUG = True in your Django settings",
    ]) {
      const { findings } = await runLive({ ...goodHome, [probe]: { status: 500, body } });
      const f = rule(findings, "WEB-L11");
      expect(f, body).toHaveLength(1);
      expect(f[0]?.severity).toBe("medium");
      expect(JSON.stringify(f[0])).not.toContain("/app/server.js");
    }
  });
  it("ignores a clean 404", async () => {
    const { findings } = await runLive({ ...goodHome, [probe]: { status: 404, body: "Not Found" } });
    expect(rule(findings, "WEB-L11")).toHaveLength(0);
  });
});
