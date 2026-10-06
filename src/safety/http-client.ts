import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import type { HttpResult, SafeHttpClient } from "../core/types.js";
import { createRateLimiter } from "./rate-limiter.js";
import { resolveAndPin } from "./ssrf-guard.js";
import type { PinnedAddress, Resolver } from "./ssrf-guard.js";

export const USER_AGENT = "whsquad/0.3.2 (+authorized-audit; https://github.com/LihanCanCode/whitehat-squad)";

const MAX_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);
const STRIPPED_HEADERS = new Set([
  "host",
  "user-agent",
  "connection",
  "content-length",
  "transfer-encoding",
  "accept-encoding",
  "upgrade",
]);

export class OutOfScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OutOfScopeError";
  }
}
export class RequestBudgetError extends Error {
  constructor(max: number) {
    super(`request budget of ${max} exhausted`);
    this.name = "RequestBudgetError";
  }
}
export class RequestTimeoutError extends Error {
  constructor(ms: number) {
    super(`request timed out after ${ms}ms`);
    this.name = "RequestTimeoutError";
  }
}

export interface PinnedInit {
  readonly method: "GET" | "HEAD";
  readonly headers: Record<string, string>;
  readonly signal: AbortSignal;
  readonly redirect: "manual";
  readonly pinned: PinnedAddress;
}
/** Transport. Production uses node:http(s) connected to the pinned IP; tests may inject. */
export type PinnedFetch = (url: string, init: PinnedInit) => Promise<Response>;

export interface SafeHttpClientOptions {
  readonly origin: URL;
  readonly maxRequests?: number;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly rps?: number;
  readonly allowPrivate?: boolean;
  /** Defaults to true only when the origin is localhost / a loopback literal. */
  readonly allowLoopback?: boolean;
  readonly resolver?: Resolver;
  /**
   * Also allow https requests to the fixed third-party backends a site can reference (a Supabase
   * project, Firestore). Off by default: ownership of the website does not prove ownership of
   * the backend it points at, so this is an explicit opt-in (`--probe-database`).
   */
  readonly allowBackendHosts?: boolean;
  /** Test seam only. */
  readonly fetchImpl?: PinnedFetch;
}

const SUPABASE_PROJECT_HOST = /^[a-z0-9]{10,30}\.supabase\.co$/;

/** Exact, fixed backend hosts only. Never a wildcard over arbitrary domains. */
export function isBackendHost(hostname: string): boolean {
  return SUPABASE_PROJECT_HOST.test(hostname) || hostname === "firestore.googleapis.com";
}

const stripBrackets = (h: string): string => (h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h);
const effectivePort = (u: URL): string => u.port || (u.protocol === "https:" ? "443" : "80");

function toWebResponse(res: http.IncomingMessage, method: string): Response {
  const headers = new Headers();
  for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
    try {
      headers.append(res.rawHeaders[i] as string, res.rawHeaders[i + 1] as string);
    } catch {
      // skip headers the Fetch implementation refuses to represent
    }
  }
  const status = res.statusCode ?? 502;
  if (method === "HEAD" || NULL_BODY_STATUSES.has(status)) {
    res.resume();
    return new Response(null, { status, headers });
  }
  const body = Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>;
  return new Response(body, { status, headers });
}

/** Default transport: dials the pinned IP, keeps the original Host header and TLS servername. */
export const pinnedFetch: PinnedFetch = (url, init) => {
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const hostname = stripBrackets(u.hostname);
  const { address, family } = init.pinned;
  return new Promise<Response>((resolve, reject) => {
    const options: https.RequestOptions = {
      hostname,
      port: effectivePort(u),
      path: `${u.pathname}${u.search}`,
      method: init.method,
      headers: { ...init.headers, host: u.host },
      agent: false,
      signal: init.signal,
      lookup: (_host, o, cb) => {
        if (typeof o === "object" && o !== null && o.all) cb(null, [{ address, family }]);
        else cb(null, address, family);
      },
    };
    if (isHttps && isIP(hostname) === 0) options.servername = hostname;
    const req = (isHttps ? https : http).request(options, (res) => {
      try {
        resolve(toWebResponse(res, init.method));
      } catch (e) {
        res.destroy();
        reject(e);
      }
    });
    req.on("error", reject);
    req.end();
  });
};

function abortable<T>(p: Promise<T>, signal: AbortSignal, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new RequestTimeoutError(ms));
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

async function readCapped(res: Response, maxBytes: number, signal: AbortSignal, ms: number): Promise<string> {
  if (!res.body || maxBytes <= 0) {
    await res.body?.cancel().catch(() => undefined);
    return "";
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await abortable(reader.read(), signal, ms);
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).subarray(0, maxBytes).toString("utf8");
}

function buildResult(res: Response, url: URL, body: string): HttpResult {
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  if (setCookies.length > 0) headers["set-cookie"] = setCookies.join(", ");
  return { url: url.href, status: res.status, headers, setCookies, body };
}

function sanitizeHeaders(extra: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = { accept: "*/*" };
  for (const [k, v] of Object.entries(extra ?? {})) {
    const key = k.toLowerCase();
    if (!STRIPPED_HEADERS.has(key)) out[key] = v;
  }
  out["user-agent"] = USER_AGENT;
  out["accept-encoding"] = "identity";
  out["connection"] = "close";
  return out;
}

function nextRedirect(from: URL, res: Response): URL | null {
  if (!REDIRECT_STATUSES.has(res.status)) return null;
  const loc = res.headers.get("location");
  if (!loc) return null;
  let to: URL;
  try {
    to = new URL(loc, from);
  } catch {
    return null;
  }
  if (to.protocol !== "http:" && to.protocol !== "https:") return null;
  if (to.username || to.password) return null;
  if (to.hostname !== from.hostname) return null;
  if (from.protocol === "https:" && to.protocol === "http:") return null;
  const upgrade = from.protocol === "http:" && to.protocol === "https:";
  if (!upgrade && effectivePort(to) !== effectivePort(from)) return null;
  return to;
}

export function createSafeHttpClient(options: SafeHttpClientOptions): SafeHttpClient {
  const maxRequests = options.maxRequests ?? 100;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const clientMaxBytes = options.maxBytes ?? 2_000_000;
  const fetchImpl = options.fetchImpl ?? pinnedFetch;
  const limiter = createRateLimiter({ rps: options.rps ?? 2 });
  const targetHost = options.origin.hostname;
  const guard = {
    allowPrivate: options.allowPrivate ?? false,
    ...(options.allowLoopback !== undefined ? { allowLoopback: options.allowLoopback } : {}),
    ...(options.resolver ? { resolver: options.resolver } : {}),
  };
  let used = 0;

  const parseInScope = (raw: string): URL => {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new OutOfScopeError("invalid URL");
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new OutOfScopeError(`unsupported scheme ${u.protocol}`);
    if (u.username || u.password) throw new OutOfScopeError("credentials in URL are not allowed");
    const isBackend = options.allowBackendHosts === true && u.protocol === "https:" && isBackendHost(u.hostname);
    if (u.hostname !== targetHost && !isBackend) {
      throw new OutOfScopeError(`host ${u.hostname} is outside the audited target ${targetHost}`);
    }
    return u;
  };

  const run = async (
    method: "GET" | "HEAD",
    raw: string,
    headerOpts: Record<string, string> | undefined,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<HttpResult> => {
    let url = parseInScope(raw);
    const headers = sanitizeHeaders(headerOpts);
    for (let hop = 0; ; hop += 1) {
      if (used >= maxRequests) throw new RequestBudgetError(maxRequests);
      used += 1;
      await abortable(limiter.acquire(), signal, timeoutMs);
      const pinned = await abortable(resolveAndPin(url.hostname, guard), signal, timeoutMs);
      const res = await abortable(
        fetchImpl(url.href, { method, headers, signal, redirect: "manual", pinned }),
        signal,
        timeoutMs,
      );
      const next = hop < MAX_REDIRECTS ? nextRedirect(url, res) : null;
      if (next) {
        await res.body?.cancel().catch(() => undefined);
        url = next;
        continue;
      }
      const body = method === "HEAD" ? "" : await readCapped(res, maxBytes, signal, timeoutMs);
      if (method === "HEAD") await res.body?.cancel().catch(() => undefined);
      return buildResult(res, url, body);
    }
  };

  const request = async (
    method: "GET" | "HEAD",
    url: string,
    headers: Record<string, string> | undefined,
    maxBytes: number,
  ): Promise<HttpResult> => {
    const signal = AbortSignal.timeout(timeoutMs);
    try {
      return await run(method, url, headers, maxBytes, signal);
    } catch (e) {
      if (signal.aborted && !(e instanceof RequestTimeoutError)) throw new RequestTimeoutError(timeoutMs);
      throw e;
    }
  };

  return {
    get: (url, opts) => request("GET", url, opts?.headers, Math.min(opts?.maxBytes ?? clientMaxBytes, clientMaxBytes)),
    head: (url, opts) => request("HEAD", url, opts?.headers, 0),
  };
}
