import { lookup } from "node:dns/promises";

export type AddressClass = "public" | "loopback" | "private" | "link-local" | "metadata" | "multicast" | "reserved";

export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}

export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export interface GuardOptions {
  /** Defaults to true only when the target itself is localhost / a loopback literal. */
  readonly allowLoopback?: boolean;
  /** RFC1918, CGNAT and ULA ranges. Defaults to false. */
  readonly allowPrivate?: boolean;
  readonly resolver?: Resolver;
}

export interface PinnedAddress {
  readonly hostname: string;
  readonly address: string;
  readonly family: 4 | 6;
  readonly addressClass: AddressClass;
}

export class SsrfBlockedError extends Error {
  constructor(
    message: string,
    readonly address: string,
    readonly addressClass: AddressClass,
  ) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

const METADATA_V4 = new Set(["169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192"]);

function parseV4Part(part: string): number | null {
  if (/^0x[0-9a-f]+$/i.test(part)) return parseInt(part, 16);
  if (/^0[0-7]+$/.test(part)) return parseInt(part, 8);
  if (/^(0|[1-9][0-9]*)$/.test(part)) return parseInt(part, 10);
  return null;
}

/** inet_aton-style parsing: decimal, octal, hex, and 1-4 part shorthand. */
function parseLooseIPv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const values: number[] = [];
  for (const p of parts) {
    const v = parseV4Part(p);
    if (v === null || !Number.isSafeInteger(v)) return null;
    values.push(v);
  }
  const last = values.pop() as number;
  const lastBytes = 5 - parts.length;
  if (last >= 256 ** lastBytes) return null;
  if (values.some((v) => v > 255)) return null;
  const tail: number[] = [];
  for (let i = lastBytes - 1; i >= 0; i -= 1) tail.push(Math.floor(last / 256 ** i) % 256);
  return [...values, ...tail];
}

function parseIPv6(input: string): number[] | null {
  let s = input.split("%")[0] ?? "";
  if (s.includes(".")) {
    const idx = s.lastIndexOf(":");
    const v4 = parseLooseIPv4(s.slice(idx + 1));
    if (idx < 0 || !v4 || s.slice(idx + 1).split(".").length !== 4) return null;
    const hi = ((v4[0] ?? 0) << 8) | (v4[1] ?? 0);
    const lo = ((v4[2] ?? 0) << 8) | (v4[3] ?? 0);
    s = `${s.slice(0, idx + 1)}${hi.toString(16)}:${lo.toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toGroups = (part: string): string[] => (part === "" ? [] : part.split(":"));
  const head = toGroups(halves[0] ?? "");
  const tail = halves.length === 2 ? toGroups(halves[1] ?? "") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  const out: number[] = [];
  for (const g of all) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

function classifyV4(o: readonly number[]): AddressClass {
  const [a = 0, b = 0, c = 0, d = 0] = o;
  const dotted = `${a}.${b}.${c}.${d}`;
  if (METADATA_V4.has(dotted)) return "metadata";
  if (a === 127) return "loopback";
  if (a === 0) return "reserved";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 100 && b >= 64 && b <= 127) return "private";
  if (a === 169 && b === 254) return "link-local";
  if (a >= 224 && a <= 239) return "multicast";
  if (a >= 240) return "reserved";
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return "reserved";
  if (a === 198 && (b === 18 || b === 19)) return "reserved";
  if (a === 198 && b === 51 && c === 100) return "reserved";
  if (a === 203 && b === 0 && c === 113) return "reserved";
  return "public";
}

const embeddedV4 = (hi: number, lo: number): number[] => [hi >> 8, hi & 255, lo >> 8, lo & 255];

function classifyV6(g: readonly number[]): AddressClass {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = g;
  const zeroUpTo4 = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  if (zeroUpTo4 && g5 === 0 && g6 === 0) return g7 === 1 ? "loopback" : "reserved";
  if (zeroUpTo4 && g5 === 0xffff) return classifyV4(embeddedV4(g6, g7));
  if (zeroUpTo4 && g5 === 0) return "reserved"; // deprecated IPv4-compatible
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return classifyV4(embeddedV4(g6, g7)); // NAT64
  }
  if (g0 === 0x2002) return classifyV4(embeddedV4(g1, g2)); // 6to4
  if (g0 === 0xfd00 && g1 === 0x0ec2 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 0x254) {
    return "metadata";
  }
  if ((g0 & 0xffc0) === 0xfe80) return "link-local";
  if ((g0 & 0xffc0) === 0xfec0) return "private";
  if ((g0 & 0xfe00) === 0xfc00) return "private";
  if (g0 >> 8 === 0xff) return "multicast";
  if (g0 === 0x2001 && (g1 === 0 || g1 === 0x0db8)) return "reserved"; // Teredo, documentation
  if (g0 >= 0x2000 && g0 <= 0x3fff) return "public";
  return "reserved";
}

function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Classifies an IP literal in any common spelling (dotted, decimal, octal, hex, shorthand,
 * IPv6, IPv4-mapped IPv6). Anything unparseable is 'reserved' (fail closed).
 */
export function classifyAddress(ip: string): AddressClass {
  const s = stripBrackets(ip.trim());
  if (s.includes(":")) {
    const groups = parseIPv6(s);
    return groups ? classifyV6(groups) : "reserved";
  }
  const v4 = parseLooseIPv4(s);
  return v4 ? classifyV4(v4) : "reserved";
}

function normalizeHost(hostname: string): string {
  const h = stripBrackets(hostname.trim().toLowerCase());
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

const isLocalhostName = (h: string): boolean => h === "localhost" || h.endsWith(".localhost");

/** Returns the canonical address if `host` is an IP literal in any spelling, else null. */
function literalAddress(host: string): { address: string; family: 4 | 6 } | null {
  if (host.includes(":")) return parseIPv6(host) ? { address: host.split("%")[0] ?? host, family: 6 } : null;
  const v4 = parseLooseIPv4(host);
  return v4 ? { address: v4.join("."), family: 4 } : null;
}

const defaultResolver: Resolver = async (hostname) => {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => ({ address: r.address, family: r.family }));
};

function isAllowed(cls: AddressClass, allowLoopback: boolean, allowPrivate: boolean): boolean {
  if (cls === "public") return true;
  if (cls === "loopback") return allowLoopback;
  if (cls === "private") return allowPrivate;
  return false;
}

/**
 * Resolves `hostname` once, rejects if ANY answer is disallowed, and returns the single
 * address the caller must connect to. Connecting to the pinned IP (not the name) defeats
 * DNS rebinding between check and use.
 */
export async function resolveAndPin(hostname: string, opts: GuardOptions = {}): Promise<PinnedAddress> {
  const host = normalizeHost(hostname);
  if (host === "") throw new SsrfBlockedError("empty hostname", "", "reserved");
  const literal = literalAddress(host);
  const allowPrivate = opts.allowPrivate ?? false;
  const allowLoopback =
    opts.allowLoopback ?? (isLocalhostName(host) || (literal !== null && classifyAddress(literal.address) === "loopback"));

  const answers: readonly ResolvedAddress[] = literal
    ? [literal]
    : await (opts.resolver ?? defaultResolver)(host);
  if (answers.length === 0) throw new SsrfBlockedError(`no addresses for ${host}`, "", "reserved");

  const classified = answers.map((a) => ({ ...a, addressClass: classifyAddress(a.address) }));
  for (const a of classified) {
    if (!isAllowed(a.addressClass, allowLoopback, allowPrivate)) {
      throw new SsrfBlockedError(
        `blocked ${a.addressClass} address ${a.address} for host ${host}`,
        a.address,
        a.addressClass,
      );
    }
  }
  const chosen = classified.find((a) => !a.address.includes(":")) ?? classified[0];
  if (!chosen) throw new SsrfBlockedError(`no addresses for ${host}`, "", "reserved");
  return {
    hostname: host,
    address: chosen.address,
    family: chosen.address.includes(":") ? 6 : 4,
    addressClass: chosen.addressClass,
  };
}
