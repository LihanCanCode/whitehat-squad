import {
  analyzeTaint, exprEnd, guardMatches, matchClose, OWNERSHIP, unitHas, type FunctionUnit, type Source,
} from "../../core/source/index.js";
import type { FileCtx, Project } from "./context.js";
import { authNames, callsGuardedHelper } from "./context.js";
import { middlewareCovers } from "./middleware.js";
import { DATA_ACCESS, MUTATION, PUBLIC_ACTION_NAME, isPagesApiPath, isPublicByDesign, isRouteHandlerPath, isWebhookPath } from "./patterns.js";
import type { Raised } from "./report-types.js";
import { codeMatches, codeMatchesInUnit, escapeRe, fileUnit, hasCode, makeHit } from "./util.js";

/** The caller is identified by asking the payment provider (Stripe success redirect), not by a session. */
const VERIFIED_BY_PROVIDER = /\bsessions\s*\.\s*retrieve\s*\(/;

function skipsPublic(f: FileCtx): boolean {
  if (isPublicByDesign(f.path)) return true;
  return isWebhookPath(f.path) && unitHas(f.src, fileUnit(f.src), "signature");
}

/** AUTH-002: handler reads/writes data without any caller check (guards are evaluated per unit). */
export function unauthenticatedHandlers(f: FileCtx, project: Project, skip: ReadonlySet<FunctionUnit> = new Set()): Raised[] {
  if (skipsPublic(f)) return [];
  const out: Raised[] = [];
  for (const u of f.handlers) {
    if (skip.has(u) || (u.action && PUBLIC_ACTION_NAME.test(u.name))) continue;
    if (codeMatchesInUnit(f.src, VERIFIED_BY_PROVIDER, u).length > 0) continue;
    if (codeMatchesInUnit(f.src, DATA_ACCESS, u).length === 0) continue;
    if (unitHas(f.src, u, "auth", { includeRouterMiddleware: true }) || codeMatchesInUnit(f.src, OWNERSHIP, u).length > 0) continue;
    if (callsGuardedHelper(f, u, "auth") || callsGuardedHelper(f, u, "ownership")) continue;
    const covered = middlewareCovers(project.middleware, f.url);
    const mutates = codeMatchesInUnit(f.src, MUTATION, u).length > 0;
    const confidence = !covered && mutates ? "high" : "medium";
    out.push({ ...makeHit(f.src, "AUTH-002", u.start), confidence });
  }
  return out;
}

const ID_KEY = String.raw`(?:id|uid|[a-z]\w*Id|\w+_id|\w+ID)`;
const KEYED = new RegExp(String.raw`(?<![\w$.])(${ID_KEY})\s*:\s*`, "g");
const SHORTHAND = new RegExp(String.raw`[{,]\s*(${ID_KEY})\s*(?=[,}])`, "g");
const FILTER_CALL = new RegExp(String.raw`\.\s*(?:eq|neq|in|match|filter|is)\s*\(\s*["'\x60](?:id|uid|\w*_id|[a-z]\w*Id)["'\x60]\s*,\s*`, "g");
const DIRECT_ID = /\.\s*(?:findById\w*|findByPk|doc|deleteById|findOneById)\s*\(\s*/g;
const SQL_ID = /\b(?:id|\w+_id|\w+Id)\s*=\s*$/i;
const DB_START = /\b(?:supabase\w*|admin|db|prisma|drizzle|knex|firestore|\w+Model)\s*\.|\bsql\s*\x60/g;
const LOOKUP = /\.(?:eq|match|filter|in)\(|\bwhere\s*:|\bwhere\(|find(?:Unique|First|One|ById)\w*\(|\.doc\(|\bWHERE\b/i;
const POST_CHECK_OR_HELPER = (t: string): boolean =>
  /^(?:!==?|===?)/.test(t) || /(?:!==?|===?)$/.test(t) || /^[A-Za-z_$][\w$]*\s*\($/.test(t);

/** Value expressions that sit in an id position inside `[start, end)`. */
function idValues(src: Source, start: number, end: number): Array<{ text: string; at: number }> {
  const code = src.code.slice(start, end);
  const out: Array<{ text: string; at: number }> = [];
  const take = (re: RegExp, group?: number): void => {
    for (const m of code.matchAll(re)) {
      const abs = start + m.index;
      if (src.bare.charAt(abs) !== src.code.charAt(abs)) continue;
      if (group !== undefined) {
        out.push({ text: m[group] ?? "", at: abs });
        continue;
      }
      const from = abs + m[0].length;
      out.push({ text: src.code.slice(from, exprEnd(src, from, true)), at: abs });
    }
  };
  take(KEYED);
  take(FILTER_CALL);
  take(DIRECT_ID);
  take(SHORTHAND, 1);
  for (const m of code.matchAll(/\$\{/g)) {
    const open = start + m.index + 1;
    const close = matchClose(src, open);
    if (close < 0 || !SQL_ID.test(src.code.slice(Math.max(0, open - 40), open - 1))) continue;
    out.push({ text: src.code.slice(open + 1, close - 1), at: open });
  }
  return out;
}

/** Ownership evidence located inside a statement: engine ownership guards plus auth-derived `name.id`. */
function ownedStatement(f: FileCtx, u: FunctionUnit, own: readonly RegExpExecArray[], start: number, end: number): boolean {
  if (own.some((m) => m.index >= start && m.index < end)) return true;
  const names = authNames(f, u).map(escapeRe);
  if (names.length === 0) return false;
  const re = new RegExp(String.raw`\b(?:${names.join("|")})\w*\??\.(?:user\??\.)?(?:id|userId|user_id|sub|uid)\b`);
  return hasCode(f.src, re, start, end);
}

/** AUTH-003: caller-supplied id used in a lookup/update/delete with no ownership filter. */
export function idorHandlers(f: FileCtx): Raised[] {
  if (isPublicByDesign(f.path)) return [];
  const { src } = f;
  const out: Raised[] = [];
  const serviceRole = hasCode(src, /SERVICE_ROLE|service_role/);
  for (const u of f.handlers) {
    const own = guardMatches(src, u, "ownership");
    if (own.some((m) => POST_CHECK_OR_HELPER(m[0].trim())) || callsGuardedHelper(f, u, "ownership")) continue;
    const taint = analyzeTaint(src, u);
    DB_START.lastIndex = u.start;
    for (let m = DB_START.exec(src.bare); m && m.index < u.end; m = DB_START.exec(src.bare)) {
      const end = exprEnd(src, m.index, false);
      const stmt = src.code.slice(m.index, end);
      if (!LOOKUP.test(stmt) || ownedStatement(f, u, own, m.index, end)) continue;
      if (!idValues(src, m.index, end).some((v) => taint.isTainted(v.text, v.at))) continue;
      const viaRls = /\bsupabase\w*\s*\./.test(stmt) && !serviceRole;
      out.push({ ...makeHit(src, "AUTH-003", m.index), confidence: viaRls ? "medium" : "high" });
      break;
    }
  }
  return out;
}

const STRIPE_CTX =
  /from\s+["']stripe["']|require\(\s*["']stripe["']\s*\)|stripe-signature|\bStripe\b|checkout\.session\.\w+|payment_intent\.\w+|invoice\.\w+|customer\.subscription\.\w+/;
const ACTS_ON_TYPE = /\b(?:event|body|payload|evt)\.type\b|switch\s*\(\s*\w+\.type\s*\)/;
const PARSES_BODY = /\b(?:req|request)\.(?:json\(\)|body\b)|JSON\.parse\(/;
const VERIFIED = /constructEvent(?:Async)?|webhooks\.construct|createHmac|timingSafeEqual/;

/** AUTH-006: Stripe webhook acting on an unverified body. */
export function unsignedStripeWebhooks(f: FileCtx): Raised[] {
  if (!isRouteHandlerPath(f.path) && !isPagesApiPath(f.path)) return [];
  const { src } = f;
  const stripeish = /stripe/i.test(f.path) || hasCode(src, STRIPE_CTX);
  if (!stripeish || !hasCode(src, ACTS_ON_TYPE) || hasCode(src, VERIFIED) || unitHas(src, fileUnit(src), "signature")) return [];
  const body = codeMatches(src, PARSES_BODY)[0];
  return body ? [makeHit(src, "AUTH-006", body.index)] : [];
}
