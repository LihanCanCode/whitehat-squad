import { exprEnd, parseBindingNames } from "../../core/source/index.js";
import { argText, findCalls, stringLiteral, type Call } from "./calls.js";
import type { FileCtx } from "./context.js";
import { skipWs } from "./context.js";
import type { Raised } from "./report-types.js";
import { escapeRe, hasCode, makeHit } from "./util.js";

// ---------------------------------------------------------------- AUTH-017

const SET_COOKIE =
  /(?:\bcookies\s*\(\s*\)|\bcookieStore|\b(?:res|response|reply)(?:\s*\.\s*cookies)?|\bctx\s*\.\s*cookies)\s*\.\s*(?:set|cookie|setCookie)\s*\(|\bsetCookie\s*\(/;
const AUTH_COOKIE_NAME = /session|token|auth|jwt|sid/i;

/** Cookie name text and the options argument, for both `(name, value, opts)` and `({ name, value, ...opts })`. */
function cookieParts(f: FileCtx, call: Call): { name: string; options: string | undefined; value: string } {
  const { src } = f;
  const offset = /\bsetCookie\s*\(/.test(src.code.slice(call.index, call.open + 1)) && !/\.\s*setCookie/.test(src.code.slice(call.index, call.open + 1)) ? 1 : 0;
  const first = argText(src, call, offset);
  if (first.startsWith("{")) {
    const name = /(?<![\w$.])name\s*:\s*([^,}]+)/.exec(first)?.[1]?.trim() ?? "";
    return { name, options: first, value: "" };
  }
  return { name: first, options: call.args[offset + 2] ? argText(src, call, offset + 2) : undefined, value: argText(src, call, offset + 1) };
}

function cookieProblem(options: string | undefined): string | undefined {
  if (options === undefined) return "no cookie options at all, so httpOnly and secure are off";
  if (!options.startsWith("{")) return undefined;
  if (/\bhttpOnly\s*:\s*false\b/.test(options)) return "httpOnly is explicitly false";
  if (/\bsecure\s*:\s*false\b/.test(options)) return "secure is explicitly false";
  if (/\.\.\./.test(options) && !/\bhttpOnly\b/.test(options)) return undefined;
  return /\bhttpOnly\s*:\s*true\b/.test(options) ? undefined : "httpOnly is not set to true";
}

function isRemoval(value: string, options: string | undefined): boolean {
  return /^(?:""|''|``)$/.test(value.trim()) || /\bmaxAge\s*:\s*0\b|expires\s*:\s*new\s+Date\(\s*0\s*\)/.test(options ?? "");
}

function authCookies(f: FileCtx): Raised[] {
  const out: Raised[] = [];
  for (const call of findCalls(f.src, SET_COOKIE)) {
    const { name, options, value } = cookieParts(f, call);
    const label = stringLiteral(name) ?? name;
    if (!AUTH_COOKIE_NAME.test(label) || !/^["'`]?[\w$.\-]+["'`]?$/.test(name.trim())) continue;
    if (isRemoval(value, options)) continue;
    const problem = cookieProblem(options);
    if (problem) out.push({ ...makeHit(f.src, "AUTH-017", call.index), variant: "cookie", note: `Cookie "${label}": ${problem}.` });
  }
  return out;
}

function jwtExpiry(f: FileCtx): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  for (const call of findCalls(src, /\b(?:jwt|jsonwebtoken|jws)\s*\.\s*sign\s*\(/)) {
    const payload = argText(src, call, 0);
    const options = call.args[2] ? argText(src, call, 2) : undefined;
    if (/(?<![\w$.])exp\s*:/.test(payload)) continue;
    if (options !== undefined && (!options.startsWith("{") || /expiresIn|noTimestamp/.test(options))) continue;
    out.push({ ...makeHit(src, "AUTH-017", call.index), variant: "jwt-expiry" });
  }
  for (const call of findCalls(src, /\bnew\s+SignJWT\s*\(/)) {
    const chain = src.code.slice(call.close, exprEnd(src, call.close, true));
    if (!/setExpirationTime|\.\s*sign\s*\(/.test(chain) || /setExpirationTime/.test(chain)) continue;
    out.push({ ...makeHit(src, "AUTH-017", call.index), variant: "jwt-expiry" });
  }
  return out;
}

const STORAGE_KEY = /token|jwt|^auth$|^authorization$/i;

function tokenStorage(f: FileCtx): Raised[] {
  const out: Raised[] = [];
  for (const call of findCalls(f.src, /\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/)) {
    const key = stringLiteral(argText(f.src, call, 0));
    if (key === undefined || !STORAGE_KEY.test(key)) continue;
    out.push({ ...makeHit(f.src, "AUTH-017", call.index), variant: /refresh/i.test(key) ? "refresh" : "storage" });
  }
  return out;
}

/** AUTH-017: auth cookies without httpOnly, jwt.sign without expiry, tokens in web storage. */
export function insecureAuthTokens(f: FileCtx): Raised[] {
  const serverSide = f.isServer || (!f.isClient && f.kind !== "client");
  return [...(serverSide ? [...authCookies(f), ...jwtExpiry(f)] : []), ...tokenStorage(f)];
}

// ---------------------------------------------------------------- AUTH-019

const HDR = String.raw`["'](?:host|origin|x-forwarded-host|referer)["']`;
const HOST_SOURCE = new RegExp(
  [
    String.raw`\.\s*get\s*\(\s*${HDR}\s*\)`,
    String.raw`\.\s*headers\s*\.\s*(?:host|origin|referer)\b`,
    String.raw`\.\s*headers\s*\[\s*${HDR}\s*\]`,
  ].join("|"),
);
const DECL = /\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])/g;
const MAIL_SINK = /\b(?:resetPasswordForEmail|signInWithOtp|inviteUserByEmail|generateLink|sendMail|sendEmail)\s*\(|\bemails\s*\.\s*send\s*\(/;
const MAX_PASSES = 3;

/** Names assigned (transitively) from a Host/Origin/Referer header. */
function headerDerivedNames(f: FileCtx): string[] {
  const { src } = f;
  const names = new Set<string>();
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    const alt = names.size > 0 ? new RegExp(String.raw`\b(?:${[...names].map(escapeRe).join("|")})\b`) : undefined;
    for (const m of src.bare.matchAll(DECL)) {
      const from = skipWs(src.bare, m.index + m[0].length);
      const end = exprEnd(src, from, true);
      const direct = hasCode(src, HOST_SOURCE, from, end);
      const viaName = alt !== undefined && hasCode(src, alt, from, end);
      if (direct || viaName) for (const n of parseBindingNames(m[1] ?? "")) names.add(n);
    }
  }
  return [...names];
}

/** AUTH-019: reset/invite/magic links built from request Host or Origin headers. */
export function hostHeaderLinks(f: FileCtx): Raised[] {
  if (f.isClient) return [];
  const calls = findCalls(f.src, MAIL_SINK);
  if (calls.length === 0) return [];
  const names = headerDerivedNames(f);
  const alt = names.length > 0 ? new RegExp(String.raw`\b(?:${names.map(escapeRe).join("|")})\b`) : undefined;
  const out: Raised[] = [];
  for (const call of calls) {
    if (hasCode(f.src, HOST_SOURCE, call.open, call.close) || (alt !== undefined && hasCode(f.src, alt, call.open, call.close))) {
      out.push(makeHit(f.src, "AUTH-019", call.index));
    }
  }
  return out;
}
