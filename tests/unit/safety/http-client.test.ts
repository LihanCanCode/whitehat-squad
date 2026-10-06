import { afterEach, describe, expect, it } from "vitest";
import {
  createSafeHttpClient,
  OutOfScopeError,
  RequestBudgetError,
  RequestTimeoutError,
  USER_AGENT,
} from "../../../src/safety/http-client.js";
import type { PinnedFetch } from "../../../src/safety/http-client.js";
import { SsrfBlockedError } from "../../../src/safety/ssrf-guard.js";
import { startMockServer } from "../../helpers/mock-server.js";
import type { MockServer } from "../../helpers/mock-server.js";

const PUBLIC_IP = "93.184.216.34";
const origin = new URL("https://app.example.test");
const publicResolver = async () => [{ address: PUBLIC_IP, family: 4 }];

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  address: string;
}

function scripted(responses: Array<() => Response>): { fetchImpl: PinnedFetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl: PinnedFetch = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, address: init.pinned.address });
    const next = responses[Math.min(calls.length - 1, responses.length - 1)];
    if (!next) throw new Error("no scripted response");
    return next();
  };
  return { fetchImpl, calls };
}

const redirect = (to: string, status = 302) => () => new Response(null, { status, headers: { location: to } });
const ok = (body = "ok") => () => new Response(body, { status: 200 });

function client(fetchImpl: PinnedFetch, extra: Partial<Parameters<typeof createSafeHttpClient>[0]> = {}) {
  return createSafeHttpClient({ origin, rps: 1000, resolver: publicResolver, fetchImpl, ...extra });
}

describe("safe http client surface", () => {
  it("exposes only get and head", () => {
    const c = client(scripted([ok()]).fetchImpl);
    expect(Object.keys(c).sort()).toEqual(["get", "head"]);
  });

  it("ignores a smuggled method option", async () => {
    const { fetchImpl, calls } = scripted([ok()]);
    const c = client(fetchImpl);
    await c.get("https://app.example.test/", { method: "DELETE" } as never);
    expect(calls[0]?.method).toBe("GET");
  });
});

describe("scope enforcement", () => {
  it("throws OutOfScopeError for other hosts, subdomains and sibling subdomains", async () => {
    const { fetchImpl, calls } = scripted([ok()]);
    const c = client(fetchImpl);
    for (const url of [
      "https://evil.test/",
      "https://sub.app.example.test/",
      "https://example.test/",
      "https://app.example.test.evil.test/",
    ]) {
      await expect(c.get(url)).rejects.toBeInstanceOf(OutOfScopeError);
    }
    expect(calls).toHaveLength(0);
  });

  it("rejects invalid URLs, non-http schemes and embedded credentials", async () => {
    const c = client(scripted([ok()]).fetchImpl);
    await expect(c.get("not a url")).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(c.get("ftp://app.example.test/")).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(c.get("https://user:pw@app.example.test/")).rejects.toBeInstanceOf(OutOfScopeError);
  });

  it("matches hostnames case-insensitively", async () => {
    const c = client(scripted([ok()]).fetchImpl);
    await expect(c.get("https://APP.Example.TEST/x")).resolves.toMatchObject({ status: 200 });
  });
});

describe("request shaping", () => {
  it("sends the fixed User-Agent, pins the resolved IP, and strips unsafe headers", async () => {
    const { fetchImpl, calls } = scripted([ok()]);
    const c = client(fetchImpl);
    await c.get("https://app.example.test/a?b=1", {
      headers: { "User-Agent": "evil", Host: "other.test", "X-Test": "1", Connection: "keep-alive" },
    });
    const call = calls[0];
    expect(call?.address).toBe(PUBLIC_IP);
    expect(call?.headers["user-agent"]).toBe(USER_AGENT);
    expect(call?.headers["x-test"]).toBe("1");
    expect(call?.headers["host"]).toBeUndefined();
    expect(call?.headers["connection"]).toBe("close");
    expect(USER_AGENT).toBe(
      "whsquad/0.3.2 (+authorized-audit; https://github.com/LihanCanCode/whitehat-squad)",
    );
  });

  it("uses HEAD for head() and returns no body", async () => {
    const { fetchImpl, calls } = scripted([() => new Response("ignored", { status: 200, headers: { "x-a": "b" } })]);
    const res = await client(fetchImpl).head("https://app.example.test/");
    expect(calls[0]?.method).toBe("HEAD");
    expect(res.body).toBe("");
    expect(res.headers["x-a"]).toBe("b");
  });
});

describe("response parsing", () => {
  it("lowercases headers and collects all set-cookie values", async () => {
    const headers = new Headers({ "Content-Type": "text/html", "X-Frame-Options": "DENY" });
    headers.append("Set-Cookie", "a=1; HttpOnly");
    headers.append("Set-Cookie", "b=2; Secure");
    const { fetchImpl } = scripted([() => new Response("hi", { status: 201, headers })]);
    const res = await client(fetchImpl).get("https://app.example.test/p");
    expect(res.status).toBe(201);
    expect(res.url).toBe("https://app.example.test/p");
    expect(res.headers["content-type"]).toBe("text/html");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.setCookies).toEqual(["a=1; HttpOnly", "b=2; Secure"]);
    expect(res.body).toBe("hi");
  });

  it("truncates the body at maxBytes (client default and per-call, never above client cap)", async () => {
    const big = "a".repeat(5000);
    const c = client(scripted([ok(big)]).fetchImpl, { maxBytes: 100 });
    expect((await c.get("https://app.example.test/")).body).toHaveLength(100);
    expect((await c.get("https://app.example.test/", { maxBytes: 10 })).body).toHaveLength(10);
    expect((await c.get("https://app.example.test/", { maxBytes: 99_999 })).body).toHaveLength(100);
  });

  it("returns an empty body for null-body responses", async () => {
    const { fetchImpl } = scripted([() => new Response(null, { status: 204 })]);
    const res = await client(fetchImpl).get("https://app.example.test/");
    expect(res.body).toBe("");
    expect(res.setCookies).toEqual([]);
  });
});

describe("request budget", () => {
  it("throws RequestBudgetError once the cap is reached", async () => {
    const { fetchImpl, calls } = scripted([ok()]);
    const c = client(fetchImpl, { maxRequests: 3 });
    for (let i = 0; i < 3; i += 1) await c.get("https://app.example.test/");
    await expect(c.get("https://app.example.test/")).rejects.toBeInstanceOf(RequestBudgetError);
    await expect(c.head("https://app.example.test/")).rejects.toBeInstanceOf(RequestBudgetError);
    expect(calls).toHaveLength(3);
  });

  it("counts redirect hops against the budget", async () => {
    const { fetchImpl, calls } = scripted([redirect("/b"), redirect("/c"), ok()]);
    const c = client(fetchImpl, { maxRequests: 2 });
    await expect(c.get("https://app.example.test/a")).rejects.toBeInstanceOf(RequestBudgetError);
    expect(calls).toHaveLength(2);
  });
});

describe("timeouts", () => {
  it("aborts a hung request that honours the signal", async () => {
    const fetchImpl: PinnedFetch = (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    await expect(client(fetchImpl, { timeoutMs: 30 }).get("https://app.example.test/")).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
  });

  it("times out even when the transport ignores the signal", async () => {
    const fetchImpl: PinnedFetch = () => new Promise<Response>(() => undefined);
    await expect(client(fetchImpl, { timeoutMs: 30 }).get("https://app.example.test/")).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
  });

  it("times out while streaming a body that never finishes", async () => {
    const fetchImpl: PinnedFetch = async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("partial"));
        },
      });
      return new Response(stream, { status: 200 });
    };
    await expect(client(fetchImpl, { timeoutMs: 50 }).get("https://app.example.test/")).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
  });
});

describe("redirect handling", () => {
  it("follows a same-host redirect, re-pinning each hop", async () => {
    const { fetchImpl, calls } = scripted([redirect("/next"), ok("final")]);
    const res = await client(fetchImpl).get("https://app.example.test/start");
    expect(res.body).toBe("final");
    expect(res.url).toBe("https://app.example.test/next");
    expect(calls.map((c) => c.url)).toEqual(["https://app.example.test/start", "https://app.example.test/next"]);
  });

  it("does NOT follow a redirect to another host; returns the 3xx", async () => {
    const { fetchImpl, calls } = scripted([redirect("https://evil.test/steal", 301)]);
    const res = await client(fetchImpl).get("https://app.example.test/");
    expect(res.status).toBe(301);
    expect(res.headers["location"]).toBe("https://evil.test/steal");
    expect(calls).toHaveLength(1);
  });

  it.each([
    "http://169.254.169.254/latest/meta-data/",
    "http://[fd00:ec2::254]/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://sub.app.example.test/",
  ])("never contacts %s via redirect", async (target) => {
    const { fetchImpl, calls } = scripted([redirect(target)]);
    const res = await client(fetchImpl).get("https://app.example.test/");
    expect(res.status).toBe(302);
    expect(calls).toHaveLength(1);
  });

  it("blocks a same-host redirect whose re-resolution turns into a metadata IP (rebinding)", async () => {
    let n = 0;
    const resolver = async () => {
      n += 1;
      return n === 1 ? [{ address: PUBLIC_IP, family: 4 }] : [{ address: "169.254.169.254", family: 4 }];
    };
    const { fetchImpl, calls } = scripted([redirect("/again"), ok()]);
    await expect(client(fetchImpl, { resolver }).get("https://app.example.test/")).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
    expect(calls).toHaveLength(1);
  });

  it("rejects the very first request when DNS already points at a private address", async () => {
    const resolver = async () => [{ address: "10.0.0.8", family: 4 }];
    const { fetchImpl, calls } = scripted([ok()]);
    await expect(client(fetchImpl, { resolver }).get("https://app.example.test/")).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
    expect(calls).toHaveLength(0);
  });

  it("allows private resolution when allowPrivate is set", async () => {
    const resolver = async () => [{ address: "10.0.0.8", family: 4 }];
    const { fetchImpl, calls } = scripted([ok()]);
    await client(fetchImpl, { resolver, allowPrivate: true }).get("https://app.example.test/");
    expect(calls[0]?.address).toBe("10.0.0.8");
  });

  it("does not follow an https -> http downgrade", async () => {
    const { fetchImpl, calls } = scripted([redirect("http://app.example.test/plain")]);
    const res = await client(fetchImpl).get("https://app.example.test/");
    expect(res.status).toBe(302);
    expect(calls).toHaveLength(1);
  });

  it("follows an http -> https upgrade on the same host", async () => {
    const { fetchImpl, calls } = scripted([redirect("https://app.example.test/"), ok("secure")]);
    const res = await client(fetchImpl, { origin: new URL("http://app.example.test") }).get(
      "http://app.example.test/",
    );
    expect(res.body).toBe("secure");
    expect(calls).toHaveLength(2);
  });

  it("does not follow a redirect to a different port", async () => {
    const { fetchImpl, calls } = scripted([redirect("https://app.example.test:8443/")]);
    const res = await client(fetchImpl).get("https://app.example.test/");
    expect(res.status).toBe(302);
    expect(calls).toHaveLength(1);
  });

  it("stops after 3 redirects and returns the last 3xx", async () => {
    const { fetchImpl, calls } = scripted([redirect("/loop")]);
    const res = await client(fetchImpl).get("https://app.example.test/loop");
    expect(res.status).toBe(302);
    expect(calls).toHaveLength(4);
  });

  it("returns a 3xx without Location, 304, and malformed Location as-is", async () => {
    for (const make of [
      () => new Response(null, { status: 302 }),
      () => new Response(null, { status: 304, headers: { location: "/x" } }),
      () => new Response(null, { status: 302, headers: { location: "http://[bad" } }),
      () => new Response(null, { status: 302, headers: { location: "ftp://app.example.test/" } }),
      () => new Response(null, { status: 302, headers: { location: "https://u:p@app.example.test/" } }),
    ]) {
      const { fetchImpl, calls } = scripted([make]);
      const res = await client(fetchImpl).get("https://app.example.test/");
      expect([302, 304]).toContain(res.status);
      expect(calls).toHaveLength(1);
    }
  });
});

describe("rate limiting", () => {
  it("acquires a token before every request", async () => {
    const { fetchImpl } = scripted([ok()]);
    const c = createSafeHttpClient({ origin, rps: 50, resolver: publicResolver, fetchImpl });
    const start = Date.now();
    for (let i = 0; i < 4; i += 1) await c.get("https://app.example.test/");
    // burst of 50 means these are instant; this just proves the default path runs.
    expect(Date.now() - start).toBeLessThan(2000);
  });
});

describe("end-to-end against a local server (real pinned transport)", () => {
  let server: MockServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  it("GETs, parses headers/cookies, sends UA, and only uses GET/HEAD", async () => {
    server = await startMockServer((req, res) => {
      res.setHeader("X-Custom", "Yes");
      res.setHeader("Set-Cookie", ["s=1; HttpOnly", "t=2"]);
      res.end(`ua=${req.headers["user-agent"] ?? ""}`);
    });
    const c = createSafeHttpClient({ origin: new URL(server.url), rps: 1000 });
    const res = await c.get(`${server.url}/hello`);
    const head = await c.head(`${server.url}/hello`);
    expect(res.status).toBe(200);
    expect(res.body).toBe(`ua=${USER_AGENT}`);
    expect(res.headers["x-custom"]).toBe("Yes");
    expect(res.setCookies).toEqual(["s=1; HttpOnly", "t=2"]);
    expect(head.body).toBe("");
    expect(server.requests.map((r) => r.method)).toEqual(["GET", "HEAD"]);
  });

  it("truncates large bodies at maxBytes", async () => {
    server = await startMockServer((_req, res) => res.end("z".repeat(100_000)));
    const c = createSafeHttpClient({ origin: new URL(server.url), rps: 1000, maxBytes: 1000 });
    const res = await c.get(`${server.url}/big`);
    expect(res.body.length).toBe(1000);
  });

  it("follows same-host redirects and stops at foreign-host redirects", async () => {
    server = await startMockServer((req, res) => {
      if (req.url === "/a") {
        res.writeHead(302, { location: "/b" }).end();
      } else if (req.url === "/b") {
        res.end("done");
      } else if (req.url === "/out") {
        res.writeHead(302, { location: "http://169.254.169.254/" }).end();
      } else {
        res.writeHead(404).end();
      }
    });
    const c = createSafeHttpClient({ origin: new URL(server.url), rps: 1000 });
    expect((await c.get(`${server.url}/a`)).body).toBe("done");
    const out = await c.get(`${server.url}/out`);
    expect(out.status).toBe(302);
    expect(out.headers["location"]).toBe("http://169.254.169.254/");
  });

  it("connects to the pinned IP while sending the original Host header", async () => {
    server = await startMockServer((req, res) => res.end(req.headers.host ?? ""));
    const target = new URL(`http://pinned.test:${server.port}`);
    const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
    const c = createSafeHttpClient({ origin: target, rps: 1000, resolver, allowLoopback: true });
    const res = await c.get(`${target.origin}/`);
    expect(res.body).toBe(`pinned.test:${server.port}`);
  });

  it("blocks a hostname resolving to loopback when loopback is not allowed", async () => {
    server = await startMockServer((_req, res) => res.end("secret"));
    const target = new URL(`http://pinned.test:${server.port}`);
    const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
    const c = createSafeHttpClient({ origin: target, rps: 1000, resolver });
    await expect(c.get(`${target.origin}/`)).rejects.toBeInstanceOf(SsrfBlockedError);
    expect(server.requests).toHaveLength(0);
  });

  it("works for the localhost hostname", async () => {
    server = await startMockServer((_req, res) => res.end("lh"));
    const target = new URL(`http://localhost:${server.port}`);
    const c = createSafeHttpClient({ origin: target, rps: 1000 });
    expect((await c.get(`${target.origin}/`)).body).toBe("lh");
  });

  it("times out a server that never answers", async () => {
    server = await startMockServer(() => undefined);
    const c = createSafeHttpClient({ origin: new URL(server.url), rps: 1000, timeoutMs: 150 });
    await expect(c.get(`${server.url}/hang`)).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("returns 204 and 5xx responses without throwing", async () => {
    server = await startMockServer((req, res) => {
      res.writeHead(req.url === "/e" ? 500 : 204).end();
    });
    const c = createSafeHttpClient({ origin: new URL(server.url), rps: 1000 });
    expect((await c.get(`${server.url}/n`)).status).toBe(204);
    expect((await c.get(`${server.url}/e`)).status).toBe(500);
  });

  it("surfaces connection errors", async () => {
    server = await startMockServer(() => undefined);
    const dead = server.url;
    await server.close();
    server = undefined;
    const c = createSafeHttpClient({ origin: new URL(dead), rps: 1000, timeoutMs: 2000 });
    await expect(c.get(`${dead}/`)).rejects.toThrow();
  });
});
