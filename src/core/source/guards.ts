import { parseBindingNames } from "./bindings.js";
import type { Source } from "./lexer.js";
import { findRouteRegistrations } from "./routes.js";
import { exprEnd, matchOpen, skipWs } from "./scan.js";
import type { Span } from "./scan.js";
import { NOT_SCHEMA_ROOTS } from "./taint.js";
import type { FunctionUnit } from "./units.js";

/**
 * ONE shared catalog of "does this code do X" checks, evaluated per unit.
 *
 * Every regex is run on `src.code` (comments blanked, strings kept so header names / column names can be
 * matched) and a match counts only if its FIRST character is real code (not inside a string, template
 * text, regex or comment). A match that starts in code and contains strings is fine, and matches that
 * start inside `${...}` are kept because `${}` content is code.
 */

export type GuardName = "auth" | "rateLimit" | "ownership" | "signature" | "validation";

export interface GuardDef {
  readonly name: GuardName;
  readonly re: RegExp;
  readonly view: "code";
  /** Optional post-filter on a raw match. */
  readonly accept?: (src: Source, m: RegExpExecArray) => boolean;
}

const OWNER_ID = String.raw`(?:id|sub|userId|uid)`;
const AUTH_ROOT = String.raw`(?:user|session|auth|claims|currentUser|viewer|authUser)\w*\??\.(?:user\??\.)?${OWNER_ID}\b`;
/** Name parts that make a verify/check/has call about something other than the caller's identity. */
const NOT_IDENTITY_WORDS = String.raw`Captcha|captcha|Csrf|csrf|Xsrf|xsrf|Email|Format|Name|Origin|Turnstile|Recaptcha|Invite|Unsubscribe`;
const NOT_IDENTITY = String.raw`(?![\w$]*(?:${NOT_IDENTITY_WORDS}))`;
/** Ownership names also exclude access *keys* and existence/definition checks. */
const NOT_OWNERSHIP = String.raw`(?![\w$]*(?:${NOT_IDENTITY_WORDS}|Key|Ownerless|Defined|Exists))`;

/** Calls that establish who the caller is (session, token, bearer secret). */
export const AUTH_CHECK = new RegExp(
  [
    String.raw`\b(?:getUser|getClaims|getSession|getServerSession|currentUser|getToken|getAuth|getAuthSession|getAuthUser|verifyToken|verifyJwt|verifyJWT|verifyIdToken|verifySessionCookie|jwtVerify|validateRequest|validateSession|validateToken|authenticate\w*|getKindeServerSession|getCurrentUser|requireAuth|requireUser|requireSession|requireAdmin|withAuth|isAuthenticated|authMiddleware|clerkClient|bearerAuth|basicAuth|checkJwt|expressjwt|expressJwt)\s*\(`,
    // middleware passed by reference: app.get('/x', requireAuth, handler)
    String.raw`\b(?:requireAuth|requireUser|requireSession|requireAdmin|withAuth|isAuthenticated|authMiddleware|ensureAuthenticated|ensureLoggedIn|checkJwt|authenticate)\b`,
    String.raw`(?<![.\w$])auth\s*\(`,
    String.raw`\bauth\s*\.\s*(?:protect\b|api\s*\.\s*getSession\b)`,
    // getCurrentUser / getServerProfile / loadSessionUser ... but not getServerSideProps, getAuthor, getUserById
    String.raw`\b(?:get|fetch|load|require|ensure|assert)(?:Current|Authenticated|Logged\w*|Session|Server|Auth\w*|Signed\w*|Active|My)(?:User|Session|Profile|Account|Viewer|Member|Admin|Identity)(?:OrThrow|OrRedirect|OrNull|Id)?\s*\(`,
    String.raw`\b(?:require|ensure|assert)(?:User|Session|Admin|Login|LoggedIn|Auth\w*)\w*\s*\(`,
    // requireRole / verifyAdmin / assertLoggedIn / checkAuthorization, but not checkUserExists
    // ...but not verifyCaptchaToken / verifyCsrfToken / validateEmailToken / checkTokenFormat / checkRoleName
    String.raw`\b${NOT_IDENTITY}(?:require|ensure|assert|check|verify|validate)\w*?(?:Auth\w*|Session|Admin|Login|LoggedIn|SignedIn|Token|Roles?|Permission\w*)\w*\s*\(`,
    String.raw`\bjwt\s*(?:\.\s*verify\b|\()`,
    // INBOUND authorization header only (an outgoing `Authorization:` header is not a check)
    String.raw`\.\s*headers?\s*(?:\.\s*authorization\b|\[\s*["'][Aa]uthorization["']\s*\])`,
    String.raw`\.\s*(?:get|header)\s*\(\s*["'][Aa]uthorization["']\s*\)`,
    String.raw`\bheaders?\s*\(\s*["'][Aa]uthorization["']\s*\)`,
    String.raw`\bgetHeader\s*\(\s*[\w$.]+\s*,\s*["'][Aa]uthorization["']`,
    String.raw`\bCRON_SECRET\b`,
    // bearer secret compare: header !== `Bearer ${process.env.X_SECRET}`
    String.raw`(?:!==?|===?)\s*\x60Bearer\s+\$\{`,
    String.raw`\x60Bearer\s+\$\{[^\x60]*\}\x60\s*(?:!==?|===?)`,
    String.raw`\b(?:req|request)\s*\.\s*(?:user|auth)\b`,
    String.raw`\b(?:locals\.user|ctx\.user|ctx\.state\.user)\b`,
    String.raw`\bsession\??\.user\b`,
    // wrapper that injects the caller: withAuth(async (req, user) => ...) / (req, { user }) =>
    String.raw`\(\s*[^()]*,\s*(?:user|session|currentUser|viewer|actor)\s*(?::[^,()]*)?\)\s*=>`,
    String.raw`\(\s*[^()]*,\s*\{[^{}]*\b(?:user|session)\b[^{}]*\}\s*(?::[^()]*)?\)\s*=>`,
  ].join("|"),
);

export const RATE_LIMIT = /rate[-_]?limit|\blimiter\b|\bthrottl\w*|\bslowDown\b/i;

/** Static ownership evidence (see {@link guardMatches} for the auth-derived-variable forms). */
export const OWNERSHIP = new RegExp(
  [
    // .eq('user_id', user.id), .eq('id', session.user.id)
    String.raw`\.\s*(?:eq|match|filter|in)\s*\(\s*[^,)]{1,40},\s*[^)\n]{0,60}?\b${AUTH_ROOT}`,
    // where: { userId: session.user.id }, ownerId: currentUser.id
    String.raw`\b[\w$]+\s*:\s*(?:await\s+)?(?:${AUTH_ROOT}|token\.sub\b)`,
    // post-fetch: doc.ownerId !== user.id
    String.raw`(?:!==?|===?)\s*[\w.?!]*\b(?:user|session|currentUser|auth)\??\.(?:user\??\.)?${OWNER_ID}\b`,
    String.raw`\b(?:user|session|currentUser)\??\.(?:user\??\.)?${OWNER_ID}\s*(?:!==?|===?)`,
    // verifyCurrentUserHasAccessToPost(id), canEdit(user, post), isOwner(...) — called with an argument;
    // not hasAccessKey / isRoleDefined / isOwnerless / isAuthorizedOrigin
    String.raw`\b${NOT_OWNERSHIP}\w*(?:verify|assert|ensure|check|authorize|require|can|has|is)\w*?(?:Access|Owner\w*|Permission\w*|Allowed|Authorized|Member|Author\b|Edit|Delete|Manage|Role)\w*\s*\((?=\s*[^\s)])`,
  ].join("|"),
);

export const SIGNATURE_CHECK =
  /\bconstructEvent(?:Async)?\b|\bwebhooks\s*\.\s*(?:construct\w*|verify\w*)|\bcreateHmac\b|\btimingSafeEqual\b|\bnew\s+Webhook\s*\(|\bverify(?:Signature|Webhook\w*|RequestSignature|Hmac|Stripe\w*|Svix\w*)\s*\(|\bvalidateSignature\s*\(|\bsubtle\s*\.\s*verify\b|\bisValidSignature\s*\(/;

const PARSE_CALL = String.raw`\.\s*(?:safeParseAsync|safeParse|parseAsync|parse|validateSync|validate)\s*\(`;
export const VALIDATION = new RegExp(
  [
    PARSE_CALL,
    String.raw`\b(?:validateBody|validateInput|validateParams|validateQuery|validatePayload|validateRequestBody|zValidator|sValidator|vValidator|tbValidator|celebrate|validationResult|checkSchema|createValidator)\s*\(`,
  ].join("|"),
);

function validationAccept(src: Source, m: RegExpExecArray): boolean {
  if (!m[0].startsWith(".")) return true;
  const b = src.bare;
  let j = m.index;
  for (let guard = 0; guard < 60; guard++) {
    while (j > 0 && /\s/.test(b.charAt(j - 1))) j--;
    const c = b.charAt(j - 1);
    if (c === ")" || c === "]") {
      const o = matchOpen(src, j - 1);
      if (o < 0) return true;
      j = o;
      continue;
    }
    if (/[\w$]/.test(c)) {
      while (j > 0 && /[\w$]/.test(b.charAt(j - 1))) j--;
      let k = j;
      while (k > 0 && /\s/.test(b.charAt(k - 1))) k--;
      if (b.charAt(k - 1) === ".") {
        j = k - 1;
        continue;
      }
    }
    break;
  }
  return !NOT_SCHEMA_ROOTS.test(b.slice(j, m.index).trim());
}

export const GUARDS: Readonly<Record<GuardName, GuardDef>> = {
  auth: { name: "auth", re: AUTH_CHECK, view: "code" },
  rateLimit: { name: "rateLimit", re: RATE_LIMIT, view: "code" },
  ownership: { name: "ownership", re: OWNERSHIP, view: "code" },
  signature: { name: "signature", re: SIGNATURE_CHECK, view: "code" },
  validation: { name: "validation", re: VALIDATION, view: "code", accept: validationAccept },
};

export interface GuardOptions {
  /** Also scan `app.use(...)` / `router.use(...)` registrations on the same receiver that precede the unit. */
  readonly includeRouterMiddleware?: boolean;
}

function execAll(src: Source, re: RegExp, range: Span, accept?: GuardDef["accept"]): RegExpExecArray[] {
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  rx.lastIndex = range.start;
  const out: RegExpExecArray[] = [];
  for (let m = rx.exec(src.code); m && m.index < range.end; m = rx.exec(src.code)) {
    if (m[0].length === 0) {
      rx.lastIndex++;
      continue;
    }
    const first = src.code.charAt(m.index);
    if (first.trim() === "" || src.bare.charAt(m.index) !== first) continue;
    if (accept && !accept(src, m)) continue;
    out.push(m);
  }
  return out;
}

const OWNER_VALUE = new RegExp(String.raw`\b${AUTH_ROOT}`);
const DECL = /\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])/g;

/** Names declared in `range` from an auth call or an auth-id expression (`const { userId } = await auth()`). */
function authDerivedNames(src: Source, range: Span): string[] {
  const names = new Set<string>();
  const rx = new RegExp(DECL.source, "g");
  rx.lastIndex = range.start;
  for (let m = rx.exec(src.bare); m && m.index < range.end; m = rx.exec(src.bare)) {
    const rhsStart = skipWs(src.bare, m.index + m[0].length);
    // Bare view: `const hint = "await getUser()"` must not make `hint` auth-derived (W7 finding).
    const text = src.bare.slice(rhsStart, exprEnd(src, rhsStart, true));
    if (AUTH_CHECK.test(text) || OWNER_VALUE.test(text)) for (const n of parseBindingNames(m[1] ?? "")) names.add(n);
  }
  return [...names];
}

function dynamicOwnership(src: Source, range: Span): RegExpExecArray[] {
  const names = authDerivedNames(src, range);
  if (names.length === 0) return [];
  const alt = names.map((n) => n.replace(/[$]/g, "\\$")).join("|");
  const re = new RegExp(
    [
      String.raw`\b[\w$]+\s*:\s*(?:${alt})\b(?!\s*[.(\[])`,
      String.raw`[{,]\s*(?:${alt})\s*[,}]`,
      String.raw`\.\s*(?:eq|match|filter|in)\s*\(\s*[^,)]{1,40},\s*(?:${alt})\s*\)`,
    ].join("|"),
  );
  return execAll(src, re, range);
}

function rangesOf(src: Source, unit: FunctionUnit, options: GuardOptions): Span[] {
  const ranges: Span[] = [{ start: unit.start, end: unit.end }, ...(unit.extraRanges ?? [])];
  if (options.includeRouterMiddleware && unit.receiver) {
    for (const reg of findRouteRegistrations(src)) {
      if (reg.method === "use" && reg.receiver === unit.receiver && reg.end <= unit.start) ranges.push({ start: reg.start, end: reg.end });
    }
  }
  return ranges;
}

/** All matches of `guard` inside the unit (and its extra ranges), as regex matches with `.index` offsets. */
export function guardMatches(src: Source, unit: FunctionUnit, guard: GuardName, options: GuardOptions = {}): RegExpExecArray[] {
  const def = GUARDS[guard];
  const out: RegExpExecArray[] = [];
  for (const range of rangesOf(src, unit, options)) {
    out.push(...execAll(src, def.re, range, def.accept));
    if (guard === "ownership") out.push(...dynamicOwnership(src, range));
  }
  return out;
}

/** Does the unit contain evidence of `guard`? (comments, strings and regexes never count) */
export function unitHas(src: Source, unit: FunctionUnit, guard: GuardName, options: GuardOptions = {}): boolean {
  return guardMatches(src, unit, guard, options).length > 0;
}
