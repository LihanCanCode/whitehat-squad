import { guardMatches, unitHas, type FunctionUnit } from "../../core/source/index.js";
import { RATE_LIMIT } from "../../core/source/index.js";
import type { FileCtx, Project } from "./context.js";
import { middlewareCovers } from "./middleware.js";
import { DATA_ACCESS, MUTATION } from "./patterns.js";
import type { Raised } from "./report-types.js";
import { codeMatchesInUnit, fileUnit, hasCode, makeHit } from "./util.js";

export interface OpsHit {
  readonly unit: FunctionUnit;
  readonly raised: Raised;
}

// ---------------------------------------------------------------- AUTH-015

const OPS_SEGMENT = /^(?:debug|seed|test|dev|internal|migrate|reset[-_]?db|db[-_]reset|admin|cron)(?:[-_][\w-]+)?$/i;
const PROD_GUARD = /process\.env\.NODE_ENV\s*(?:===|!==|==|!=)\s*["']production["']|\bisProduction\b|\bVERCEL_ENV\b/;
const SECRET_HEADER =
  /\.\s*(?:get|header)\s*\(\s*["'][\w-]*(?:secret|key|token)[\w-]*["']\s*\)|\.\s*headers\s*\[\s*["'][\w-]*(?:secret|key|token)[\w-]*["']\s*\]|\bADMIN_(?:SECRET|KEY|TOKEN)\b|\bAPI_SECRET\b/i;
const DESTRUCTIVE =
  /\bmigrate\s*\(|\bexecSync\s*\(|\bexec\s*\(|\bspawn(?:Sync)?\s*\(|\.\s*(?:deleteMany|truncate|dropTable|dropDatabase)\s*\(|\bprocess\.env(?![.\w[])/;
const DESTRUCTIVE_SQL = /\bdrop\s+(?:table|schema|database)\b|\btruncate\s+table\b|\bdelete\s+from\b/i;
const SIDE_EFFECT = /\bfetch\s*\(|\.\s*sendMail\s*\(|\bsendEmail\s*\(|\.\s*send\s*\(\s*\{/;

function routeSegments(path: string): string[] {
  return path.replace(/\\/g, "/").split("/").filter((s) => s !== "" && !/^\(.*\)$/.test(s)).map((s) => s.replace(/\.[a-z]+$/, ""));
}

function isOpsRoute(f: FileCtx, u: FunctionUnit): boolean {
  if (f.kind !== "route" && f.kind !== "pagesApi" && f.kind !== "express") return false;
  const segs = f.kind === "express" ? (u.route ?? "").split("/").filter(Boolean) : routeSegments(f.path).filter((s) => s !== "route");
  return segs.some((s) => OPS_SEGMENT.test(s));
}

function isDestructive(f: FileCtx, u: FunctionUnit): boolean {
  return codeMatchesInUnit(f.src, DESTRUCTIVE, u).length > 0 || DESTRUCTIVE_SQL.test(f.src.code.slice(u.start, u.end));
}

function isProtectedOps(f: FileCtx, u: FunctionUnit): boolean {
  const { src } = f;
  return (
    unitHas(src, u, "auth", { includeRouterMiddleware: true }) ||
    unitHas(src, u, "signature") ||
    codeMatchesInUnit(src, PROD_GUARD, u).length > 0 ||
    codeMatchesInUnit(src, SECRET_HEADER, u).length > 0
  );
}

/** AUTH-015: debug/seed/cron/admin route with no auth, shared secret or production guard. */
export function operationsRoutes(f: FileCtx, project: Project): OpsHit[] {
  if (f.isClient || middlewareCovers(project.middleware, f.url)) return [];
  const out: OpsHit[] = [];
  for (const u of f.handlers) {
    if (!isOpsRoute(f, u) || isProtectedOps(f, u)) continue;
    const destructive = isDestructive(f, u);
    const active =
      destructive || codeMatchesInUnit(f.src, DATA_ACCESS, u).length > 0 || codeMatchesInUnit(f.src, MUTATION, u).length > 0 ||
      codeMatchesInUnit(f.src, SIDE_EFFECT, u).length > 0;
    if (!active) continue;
    out.push({ unit: u, raised: { ...makeHit(f.src, "AUTH-015", u.start), ...(destructive ? { variant: "critical" } : {}) } });
  }
  return out;
}

// ---------------------------------------------------------------- AUTH-014

const AUTH_PATH =
  /^(?:login|log-in|signin|sign-in|signup|sign-up|register|forgot|forgot[-_]?password|reset|reset[-_]?password|password[-_]?reset|otp|send[-_]?otp|verify|verify[-_]?(?:otp|code|email|phone)|magic[-_]?link)$/i;
const AUTH_ACTION =
  /^(?:login|log_?in|sign_?in|sign_?up|register|forgot\w*|reset\w*pass\w*|request\w*reset\w*|send\w*(?:otp|code|magic)\w*|verify(?:otp|code|email|phone)\w*|otp\w*|magic\w*)$/i;
const PROVIDER_CALL = /\.\s*auth\s*\.\s*(?:signIn\w*|signUp|resetPasswordForEmail|verifyOtp)\b|\bsignIn\s*\(|\bclerkClient\b|\bsendPasswordResetEmail\b|\bsignInWith\w+\s*\(|\bcreateUserWithEmailAndPassword\b/;

function isAuthEndpoint(f: FileCtx, u: FunctionUnit): boolean {
  if (f.kind === "action" || u.action) return AUTH_ACTION.test(u.name);
  if (f.kind === "route") return u.httpMethod === "POST" && routeSegments(f.path).some((s) => AUTH_PATH.test(s));
  if (f.kind === "pagesApi") return routeSegments(f.path).some((s) => AUTH_PATH.test(s));
  if (f.kind === "express") {
    return (u.httpMethod === "POST" || u.httpMethod === "ALL") && (u.route ?? "").split("/").some((s) => AUTH_PATH.test(s));
  }
  return false;
}

/** AUTH-014: credential / recovery endpoint with no rate limiting anywhere it could come from. */
export function unthrottledAuthEndpoints(f: FileCtx, project: Project): Raised[] {
  if (!f.isServer || project.hasMiddlewareRateLimit || /\[\.\.\.nextauth\]/.test(f.path)) return [];
  if (hasCode(f.src, RATE_LIMIT) || guardMatches(f.src, fileUnit(f.src), "rateLimit").length > 0) return [];
  const out: Raised[] = [];
  for (const u of f.handlers) {
    if (!isAuthEndpoint(f, u) || unitHas(f.src, u, "rateLimit", { includeRouterMiddleware: true })) continue;
    const delegated = codeMatchesInUnit(f.src, PROVIDER_CALL, u).length > 0;
    // A hosted provider's sign-in (Supabase, Firebase, Clerk) is throttled server-side: low severity, not medium.
    out.push({
      ...makeHit(f.src, "AUTH-014", u.start),
      ...(delegated ? { variant: "hosted" } : {}),
      confidence: delegated || project.hasAuthProvider ? "low" : "medium",
    });
  }
  return out;
}
