import { exprEnd } from "../../core/source/index.js";
import { argText, findCalls, initializerOf, stringLiteral } from "./calls.js";
import type { FileCtx } from "./context.js";
import { skipWs } from "./context.js";
import type { Raised } from "./report-types.js";
import { codeMatches, makeHit } from "./util.js";

// ---------------------------------------------------------------- AUTH-012 weak randomness

const WEAK_SOURCE = /\bMath\s*\.\s*random\s*\(\s*\)|\bDate\s*\.\s*now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)\s*\.\s*getTime\s*\(\s*\)/;
const SECRET_WORDS = new Set(["token", "otp", "secret", "password", "passwd", "pwd", "nonce", "apikey", "salt", "csrf", "sid", "passcode"]);
const CODE_QUALIFIERS = new Set(["verification", "verify", "confirm", "confirmation", "auth", "login", "sms", "email", "mfa", "otp", "reset", "invite", "access", "security", "activation", "pairing", "magic", "recovery"]);
const TIME_WORDS = new Set(["expiry", "expires", "expire", "expiration", "exp", "at", "time", "ttl", "duration", "count", "start", "started", "age", "created", "updated", "timestamp", "delay", "interval", "ms", "seconds", "date"]);
const MAX_GENERATOR_LENGTH = 800;

function words(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

/** Does this identifier name a value that must be unguessable (token, otp, reset code, session id...)? */
export function isSecretName(name: string): boolean {
  const w = words(name);
  if (w.some((x) => TIME_WORDS.has(x))) return false;
  if (w.some((x) => SECRET_WORDS.has(x))) return true;
  if (w.includes("api") && w.includes("key")) return true;
  if (w.includes("session") && w.some((x) => ["id", "key", "token", "secret", "cookie"].includes(x))) return true;
  if (w.includes("code") && (w.length === 1 || w.some((x) => CODE_QUALIFIERS.has(x)))) return true;
  return w.some((x) => x === "invite" || x === "reset" || x === "magic") && w.some((x) => ["id", "key", "link", "url", "hash", "code"].includes(x));
}

const BINDINGS: readonly RegExp[] = [
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])/g,
  /(?<![\w$.=!<>])([A-Za-z_$][\w$]*)\s*=(?![=>])/g,
  /(?<![\w$.])([A-Za-z_$][\w$]*)\s*:\s*/g,
];

function isServerish(f: FileCtx): boolean {
  if (f.isClient || f.kind === "client") return false;
  if (/(?:^|\/)(?:components|hooks|ui)\//.test(f.path)) return false;
  return f.isServer || !/\.(?:tsx|jsx)$/.test(f.path);
}

/** AUTH-012: Math.random()/Date.now() used to make a token, otp, secret, password, nonce or session id. */
export function weakRandomness(f: FileCtx): Raised[] {
  if (!isServerish(f)) return [];
  const { src } = f;
  const seen = new Set<number>();
  const out: Raised[] = [];
  const hit = (offset: number): void => {
    const line = src.raw.slice(0, offset).split("\n").length;
    if (seen.has(line)) return;
    seen.add(line);
    out.push({ ...makeHit(src, "AUTH-012", offset), confidence: f.isServer ? "high" : "medium" });
  };
  for (const re of BINDINGS) {
    for (const m of src.bare.matchAll(re)) {
      if (!isSecretName(m[1] ?? "")) continue;
      const rhs = skipWs(src.bare, m.index + m[0].length);
      const end = exprEnd(src, rhs, true);
      const text = src.bare.slice(rhs, end);
      if (/=>|\bfunction\b/.test(text) && text.length > MAX_GENERATOR_LENGTH) continue;
      const weak = WEAK_SOURCE.exec(text);
      if (weak) hit(rhs + weak.index);
    }
  }
  for (const u of f.units) {
    if (!isSecretName(u.name) || u.end - u.start > MAX_GENERATOR_LENGTH) continue;
    const weak = WEAK_SOURCE.exec(src.bare.slice(u.start, u.end));
    if (weak) hit(u.start + weak.index);
  }
  return out;
}

// ---------------------------------------------------------------- AUTH-013 password storage

const PWD = /\b(?:passw(?:or)?d|pwd|passphrase|pass)\w*/i;
const FAST_HASHES = new Set(["md5", "sha1", "sha256"]);
const MIN_BCRYPT_ROUNDS = 10;
const HASHER = /\b(?:bcrypt\w*|argon2\w*|scrypt\w*|pbkdf2\w*|\w*[hH]ash\w*|encrypt\w*)\b/;
const PROVIDER_SIGNUP = /\b(?:signUp|signInWithPassword|createUser|updateUser|auth\s*\.\s*admin|createUserWithEmailAndPassword)\b/;

function fastHashes(f: FileCtx): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  for (const call of findCalls(src, /\bcreateHash\s*\(/)) {
    const algo = (stringLiteral(argText(src, call, 0)) ?? "").toLowerCase().replace("-", "");
    if (!FAST_HASHES.has(algo)) continue;
    const chain = src.bare.slice(call.close, exprEnd(src, call.close, true));
    const update = /^\s*\.\s*update\s*\(/.exec(chain);
    if (!update) continue;
    const open = call.close + update[0].length - 1;
    let depth = 0;
    let close = open;
    for (; close < src.bare.length; close++) {
      const c = src.bare.charAt(close);
      if (c === "(") depth++;
      else if (c === ")" && --depth === 0) break;
    }
    if (PWD.test(src.bare.slice(open, close))) out.push({ ...makeHit(src, "AUTH-013", call.index), variant: "hash" });
  }
  for (const call of findCalls(src, /\b(?:CryptoJS\s*\.\s*)?(?:MD5|SHA1|SHA256|md5|sha1|sha256)\s*\(/)) {
    if (PWD.test(src.bare.slice(call.open, call.close))) out.push({ ...makeHit(src, "AUTH-013", call.index), variant: "hash" });
  }
  return out;
}

function numericArg(f: FileCtx, text: string): number | undefined {
  const t = /^\d+$/.test(text.trim()) ? text.trim() : /^[A-Za-z_$][\w$]*$/.test(text.trim()) ? initializerOf(f.src, text.trim()) : undefined;
  return t !== undefined && /^\d+$/.test(t) ? Number(t) : undefined;
}

function bcryptRounds(f: FileCtx): Raised[] {
  const { src } = f;
  if (!/["']bcrypt(?:js|-ts)?["']/.test(src.code)) return [];
  const out: Raised[] = [];
  const calls = [
    ...findCalls(src, /\.\s*(?:hash|hashSync)\s*\(/).map((c) => ({ c, i: 1 })),
    ...findCalls(src, /\.\s*(?:genSalt|genSaltSync)\s*\(/).map((c) => ({ c, i: 0 })),
  ];
  for (const { c, i } of calls) {
    const rounds = numericArg(f, argText(src, c, i));
    if (rounds !== undefined && rounds >= 1 && rounds < MIN_BCRYPT_ROUNDS) {
      out.push({ ...makeHit(src, "AUTH-013", c.index), variant: "rounds", note: `Cost factor ${rounds} is below the minimum of ${MIN_BCRYPT_ROUNDS}.` });
    }
  }
  return out;
}

const PLAIN_EQ = [
  /\b[\w$]+\??\.(?:password|passwd|pwd)\s*(?:===?|!==?)\s*[\w$.?]*(?:password|passwd|pwd)\b/i,
  /\b[\w$.?]*(?:password|passwd|pwd)\s*(?:===?|!==?)\s*[\w$]+\??\.(?:password|passwd|pwd)\b/i,
];
const STORE_CALL = /\.\s*(?:create|createMany|insert|values|save|update|set|upsert|insertOne)\s*\(/;
const PLAIN_VALUE = /^(?:[\w$.?!]*\b(?:password|pwd|passwd)\b[\w$.?!]*|[\w$.?]*\.get\(\s*["']password["']\s*\)[\s\w!]*)$/i;

function plaintext(f: FileCtx): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  for (const u of f.units) {
    if (u.kind === "handler" || u.exported || u.action) {
      const body = src.bare.slice(u.start, u.end);
      if (HASHER.test(body) || /\bcompare(?:Sync)?\s*\(/.test(body)) continue;
      for (const re of PLAIN_EQ) {
        for (const m of codeMatches(src, re, u.start, u.end)) {
          if (/confirm|repeat|retype|again|new|old/i.test(m[0])) continue;
          out.push({ ...makeHit(src, "AUTH-013", m.index), variant: "plaintext" });
        }
      }
      if (PROVIDER_SIGNUP.test(body)) continue;
      for (const call of findCalls(src, STORE_CALL, u.start, u.end)) {
        if (storesPlainPassword(f, call.open, call.close)) out.push({ ...makeHit(src, "AUTH-013", call.index), variant: "plaintext" });
      }
    }
  }
  return out;
}

function storesPlainPassword(f: FileCtx, open: number, close: number): boolean {
  const { src } = f;
  for (const m of codeMatches(src, /(?<![\w$.])(?:password|passwd|pwd)\s*:\s*/, open, close)) {
    const from = m.index + m[0].length;
    const value = src.code.slice(from, exprEnd(src, from, true)).trim();
    if (PLAIN_VALUE.test(value) && !HASHER.test(value)) return true;
  }
  return codeMatches(src, /[{,]\s*(?:password|passwd|pwd)\s*(?=[,}])/, open, close).length > 0;
}

/** AUTH-013: fast password hashes, low bcrypt cost, plaintext compare or storage. */
export function weakPasswordHandling(f: FileCtx): Raised[] {
  if (f.isClient) return [];
  const all = [...fastHashes(f), ...bcryptRounds(f), ...plaintext(f)];
  const seen = new Set<string>();
  return all.filter((r) => (seen.has(`${r.line}:${r.variant}`) ? false : (seen.add(`${r.line}:${r.variant}`), true)));
}
