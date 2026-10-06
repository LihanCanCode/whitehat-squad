import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createSafeHttpClient } from "./http-client.js";
import { classifyAddress } from "./ssrf-guard.js";
import type { Resolver } from "./ssrf-guard.js";

export type OwnershipMethod = "loopback" | "dns-txt" | "well-known" | "private-allowed" | "none";

export interface OwnershipResult {
  readonly verified: boolean;
  readonly method: OwnershipMethod;
  readonly detail: string;
}

export interface Proof {
  readonly domain: string;
  readonly token: string;
}

export type Fetcher = (url: string) => Promise<{ status: number; body: string }>;

export interface VerifyOptions {
  readonly token?: string;
  /** Directory holding .whsquad/proof.json. Defaults to cwd. */
  readonly dir?: string;
  readonly allowPrivate?: boolean;
  readonly resolveTxt?: (name: string) => Promise<string[][]>;
  readonly fetcher?: Fetcher;
  /** DNS resolver used by the default (safe-client) fetcher. */
  readonly resolver?: Resolver;
}

const PROOF_DIR = ".whsquad";
const PROOF_FILE = "proof.json";
const TOKEN_RE = /^[0-9a-f]{32}$/;
const MAX_WELL_KNOWN_BYTES = 1024;
const TXT_PREFIX = "whsquad-verify=";

const stripBrackets = (h: string): string => (h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h);

export function readProof(dir: string): Proof | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(dir, PROOF_DIR, PROOF_FILE), "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const { domain, token } = parsed as Record<string, unknown>;
    if (typeof domain !== "string" || typeof token !== "string" || !TOKEN_RE.test(token)) return null;
    return { domain, token };
  } catch {
    return null;
  }
}

/** Creates (or reuses, for the same domain) a 128-bit proof token in <dir>/.whsquad/proof.json. */
export function createProof(domain: string, dir: string): { token: string; file: string } {
  const file = join(dir, PROOF_DIR, PROOF_FILE);
  const existing = readProof(dir);
  if (existing && existing.domain === domain) return { token: existing.token, file };
  const token = randomBytes(16).toString("hex");
  mkdirSync(join(dir, PROOF_DIR), { recursive: true });
  writeFileSync(file, JSON.stringify({ domain, token, createdAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  try {
    chmodSync(file, 0o600);
  } catch {
    // best effort (e.g. Windows)
  }
  return { token, file };
}

function safeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

function txtMatches(records: readonly (readonly string[])[], token: string): boolean {
  let matched = false;
  for (const chunks of records) {
    const record = chunks.join("").trim();
    if (!record.startsWith(TXT_PREFIX)) continue;
    if (safeEqual(record.slice(TXT_PREFIX.length).trim(), token)) matched = true;
  }
  return matched;
}

function bodyMatches(body: string, token: string): boolean {
  let matched = false;
  for (const word of body.slice(0, MAX_WELL_KNOWN_BYTES).trim().split(/\s+/)) {
    const candidate = word.startsWith(TXT_PREFIX) ? word.slice(TXT_PREFIX.length) : word;
    if (safeEqual(candidate, token)) matched = true;
  }
  return matched;
}

function classifyTarget(host: string, allowPrivate: boolean): OwnershipResult | null {
  // Only the bare name: "x.localhost" may resolve to a public address on some resolvers.
  if (host === "localhost") {
    return { verified: true, method: "loopback", detail: "loopback target is auto-verified" };
  }
  // Numeric literal forms only (127.1, 0x7f000001, 2130706433). A name like "face.de" is a domain.
  const isLiteral = host.includes(":") || /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$/i.test(host);
  if (!isLiteral) return null;
  const cls = classifyAddress(host);
  if (cls === "loopback") return { verified: true, method: "loopback", detail: "loopback target is auto-verified" };
  if (cls === "private") {
    return allowPrivate
      ? { verified: true, method: "private-allowed", detail: "private address allowed by --allow-private" }
      : { verified: false, method: "none", detail: "private address: re-run with --allow-private if you own this network" };
  }
  if (cls === "public") return null;
  return { verified: false, method: "none", detail: `${cls} addresses can never be verified` };
}

function defaultFetcher(target: URL, resolver: Resolver | undefined, allowPrivate: boolean): Fetcher {
  return async (url) => {
    const client = createSafeHttpClient({
      origin: target,
      maxRequests: 4,
      maxBytes: MAX_WELL_KNOWN_BYTES,
      timeoutMs: 5000,
      allowPrivate,
      ...(resolver ? { resolver } : {}),
    });
    const res = await client.get(url);
    return { status: res.status, body: res.body };
  };
}

export async function verifyOwnership(target: URL, opts: VerifyOptions = {}): Promise<OwnershipResult> {
  const host = stripBrackets(target.hostname.toLowerCase());
  const early = classifyTarget(host, opts.allowPrivate ?? false);
  if (early) return early;

  // A token created for another domain proves nothing about this one.
  const proof = opts.token ? null : readProof(opts.dir ?? process.cwd());
  const token = opts.token ?? (proof && proof.domain.toLowerCase() === host ? proof.token : undefined);
  if (!token) {
    return { verified: false, method: "none", detail: "no proof token found in .whsquad/proof.json" };
  }

  const resolveTxt = opts.resolveTxt ?? ((name: string) => dnsResolveTxt(name));
  try {
    if (txtMatches(await resolveTxt(`_whsquad.${host}`), token)) {
      return { verified: true, method: "dns-txt", detail: `TXT record at _whsquad.${host} matched` };
    }
  } catch {
    // no TXT record; try the next method
  }

  const wellKnown = `https://${target.host}/.well-known/whsquad.txt`;
  const fetcher = opts.fetcher ?? defaultFetcher(new URL(`https://${target.host}`), opts.resolver, opts.allowPrivate ?? false);
  try {
    const res = await fetcher(wellKnown);
    if (res.status === 200 && bodyMatches(res.body, token)) {
      return { verified: true, method: "well-known", detail: `${wellKnown} matched` };
    }
  } catch {
    // unreachable or blocked; fall through
  }
  return {
    verified: false,
    method: "none",
    detail: `no matching proof at TXT _whsquad.${host} or ${wellKnown}`,
  };
}
