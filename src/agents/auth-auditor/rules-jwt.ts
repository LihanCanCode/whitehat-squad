import { redactSecret } from "../../safety/redact.js";
import type { FileCtx } from "./context.js";
import { argText, findCalls, initializerOf, outermostUnit, stringLiteral, type Call } from "./calls.js";
import type { Raised } from "./report-types.js";
import { codeMatches, hasCode, makeHit } from "./util.js";

const ALG_NONE = /\balgorithms?\s*:\s*\[[^\]]*["']none["']|\balg(?:orithm)?\s*:\s*["']none["']/i;
const SIGN_OR_VERIFY = /\b(?:jwt|jsonwebtoken|jws)\s*\.\s*(?:sign|verify)\s*\(/;
const NAMED_SIGN_VERIFY = /\b(?:sign|verify)\s*\(/;
const NAMED_IMPORT = /import\s*\{[^}]*\b(?:sign|verify)\b[^}]*\}\s*from\s*["']jsonwebtoken["']/;
const TEXT_ENCODER = /new\s+TextEncoder\s*\(\s*\)\s*\.\s*encode\s*\(/;
const ENV_FALLBACK = /^(?:process\.env|import\.meta\.env)(?:\.[\w$]+|\[[^\]]+\])\s*(?:\|\||\?\?)\s*([\s\S]+)$/;
const MIN_SECRET = 3;

/** Reads a hard-coded secret out of an argument: a literal, `process.env.X || "literal"`, or a const holding one. */
function literalSecret(f: FileCtx, text: string, depth = 0): string | undefined {
  const t = text.trim();
  const lit = stringLiteral(t);
  if (lit !== undefined) return lit.length >= MIN_SECRET ? lit : undefined;
  const fallback = ENV_FALLBACK.exec(t);
  if (fallback) {
    const v = stringLiteral((fallback[1] ?? "").replace(/\)+$/, ""));
    return v !== undefined && v.length >= MIN_SECRET ? v : undefined;
  }
  const enc = /^new\s+TextEncoder\s*\(\s*\)\s*\.\s*encode\s*\(([\s\S]*)\)$/.exec(t);
  if (enc) return literalSecret(f, enc[1] ?? "", depth);
  if (depth === 0 && /^[A-Za-z_$][\w$]*$/.test(t)) {
    const init = initializerOf(f.src, t);
    return init === undefined ? undefined : literalSecret(f, init, 1);
  }
  return undefined;
}

function secretHits(f: FileCtx, calls: readonly Call[], argIndex: number, onSecret: (s: string) => void): Raised[] {
  const out: Raised[] = [];
  for (const call of calls) {
    const secret = literalSecret(f, argText(f.src, call, argIndex));
    if (secret === undefined) continue;
    onSecret(secret);
    const hit = makeHit(f.src, "AUTH-004", call.index);
    const snippet = hit.snippet.split(secret).join(redactSecret(secret));
    out.push({ ...hit, snippet, variant: "secret" });
  }
  return out;
}

const VERIFY_CALLS = [
  /\b(?:jwt|jsonwebtoken|jws)\s*\.\s*verify\s*\(/,
  /\bjwtVerify\s*\(/,
  /\b(?:verifyJwt|verifyJWT|verifyToken|verifyAccessToken|verifyIdToken|verifySessionToken)\s*\(/,
  /\.\s*auth\s*\.\s*getUser\s*\(/,
];

/** Is the token passed to `decode` also checked by a signature-verifying call (same unit, or same token variable)? */
function isVerifiedElsewhere(f: FileCtx, decode: Call): boolean {
  const token = argText(f.src, decode, 0);
  const unit = outermostUnit(f, decode.index);
  for (const re of VERIFY_CALLS) {
    for (const v of findCalls(f.src, re)) {
      if (unit && v.index >= unit.start && v.index < unit.end) return true;
      if (token !== "" && argText(f.src, v, 0) === token) return true;
    }
  }
  return false;
}

function isServerSideJwt(f: FileCtx): boolean {
  if (f.isClient) return false;
  return f.kind === "route" || f.kind === "pagesApi" || f.kind === "middleware" || f.kind === "action" ||
    f.kind === "express" || /(?:^|\/)(?:server|api|backend)\//.test(f.path);
}

/** AUTH-004: decode-instead-of-verify, alg none, hard-coded signing secrets. */
export function jwtMisuse(f: FileCtx, registerSecret: (value: string) => void): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  for (const m of codeMatches(src, ALG_NONE)) out.push({ ...makeHit(src, "AUTH-004", m.index), variant: "none" });

  const signVerify = findCalls(src, SIGN_OR_VERIFY);
  if (NAMED_IMPORT.test(src.code)) signVerify.push(...findCalls(src, NAMED_SIGN_VERIFY));
  out.push(...secretHits(f, signVerify, 1, registerSecret));
  const jose = hasCode(src, /\bjose\b|\bjwtVerify\b|\bSignJWT\b/) || /["']jose["']/.test(src.code);
  if (jose) out.push(...secretHits(f, findCalls(src, TEXT_ENCODER), 0, registerSecret));

  if (hasCode(src, /\bcreateRemoteJWKSet\b/)) return out;
  const serverSide = isServerSideJwt(f);
  const trusted = /["']jsonwebtoken["']/.test(src.code);
  for (const call of findCalls(src, /\bjwt\s*\.\s*decode\s*\(/)) {
    if (f.isClient || isVerifiedElsewhere(f, call)) continue;
    out.push({ ...makeHit(src, "AUTH-004", call.index), variant: "decode", confidence: trusted || serverSide ? "high" : "medium" });
  }
  if (serverSide) {
    for (const call of findCalls(src, /\b(?:jwtDecode|decodeJwt|jwt_decode)\s*\(/)) {
      if (isVerifiedElsewhere(f, call)) continue;
      out.push({ ...makeHit(src, "AUTH-004", call.index), variant: "decode", confidence: "medium" });
    }
  }
  return out;
}
