import { guardMatches, type Source } from "../../core/source/index.js";
import { RATE_LIMIT } from "../../core/source/index.js";
import { codeMatches, fileUnit, hasCode } from "./util.js";

/** What a Next.js middleware file actually enforces: which URLs it matches and whether it checks the caller. */
export interface MiddlewareInfo {
  readonly path: string;
  readonly matchers: readonly RegExp[] | "all";
  readonly authenticates: boolean;
  readonly rateLimits: boolean;
}

/** Helpers and library middlewares that authenticate by name, for code that delegates to an import. */
const AUTH_DELEGATE =
  /\b(?:updateSession|clerkMiddleware|authMiddleware|withClerkMiddleware|withAuth|NextAuth|authkitMiddleware|convexAuthNextjsMiddleware|handleAuth|auth\.protect|getToken|createMiddlewareClient|createMiddlewareSupabaseClient|updateSupabaseSession|protectRoute|requireAuth|isAuthenticated|verifyAuth|checkAuth)\b/;
const AUTH_REEXPORT =
  /export\s*\{[^}]*\bauth\b[^}]*\bas\s+(?:middleware|proxy)\b[^}]*\}|export\s*\{\s*default\s*\}\s*from\s*["'](?:next-auth\/middleware|@clerk\/nextjs[^"']*)["']|export\s+default\s+(?:auth|withAuth|clerkMiddleware|authMiddleware)\b/;

function quoted(code: string): string[] {
  return [...code.matchAll(/(["'`])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2] ?? "");
}

/** Extract `matcher` entries from `export const config = { matcher: ... }`; "all" when none is declared. */
function matcherPatterns(src: Source): string[] | "all" {
  const cfg = codeMatches(src, /\bexport\s+const\s+config\s*(?::[^=]+)?=\s*\{/)[0];
  if (!cfg) return "all";
  const key = codeMatches(src, /\bmatcher\s*:/, cfg.index)[0];
  if (!key) return "all";
  let i = key.index + key[0].length;
  while (/\s/.test(src.code.charAt(i))) i++;
  const start = i;
  if (src.code.charAt(i) === "[") {
    let depth = 0;
    for (; i < src.code.length; i++) {
      const c = src.code.charAt(i);
      if (c === "[") depth++;
      else if (c === "]" && --depth === 0) break;
    }
    return quoted(src.code.slice(start, i + 1));
  }
  return quoted(src.code.slice(start, src.code.indexOf("\n", start) === -1 ? undefined : src.code.indexOf("\n", start)));
}

/** path-to-regexp style matcher to an anchored, case-insensitive RegExp; null when it cannot be parsed. */
export function matcherToRegExp(pattern: string): RegExp | null {
  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern.charAt(i);
    if (c === "(") {
      let depth = 0;
      let j = i;
      for (; j < pattern.length; j++) {
        if (pattern.charAt(j) === "\\") j++;
        else if (pattern.charAt(j) === "(") depth++;
        else if (pattern.charAt(j) === ")" && --depth === 0) break;
      }
      out += pattern.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    const param = /^\/?:\w+([*+?]?)/.exec(pattern.slice(i));
    if (param) {
      const slash = pattern.charAt(i) === "/";
      const mod = param[1];
      if (mod === "*") out += "(?:/.*)?";
      else if (mod === "+") out += "/.+";
      else if (mod === "?") out += "(?:/[^/]+)?";
      else out += slash ? "/[^/]+" : "[^/]+";
      i += param[0].length;
      continue;
    }
    out += c === "*" ? ".*" : c.replace(/[.+?^${}|[\]\\]/g, "\\$&");
    i++;
  }
  try {
    return new RegExp(`^${out}/?$`, "i");
  } catch {
    return null;
  }
}

export function analyzeMiddleware(src: Source): MiddlewareInfo {
  const unit = fileUnit(src);
  const authenticates =
    guardMatches(src, unit, "auth").length > 0 || hasCode(src, AUTH_DELEGATE) || AUTH_REEXPORT.test(src.code);
  const patterns = matcherPatterns(src);
  const matchers = patterns === "all" ? "all" : patterns.map(matcherToRegExp).filter((r): r is RegExp => r !== null);
  return {
    path: src.path,
    matchers: matchers === "all" || matchers.length === 0 ? "all" : matchers,
    authenticates,
    rateLimits: hasCode(src, RATE_LIMIT),
  };
}

/** Does any authenticating middleware cover `url`? An unknown url counts as covered when a middleware matches broadly. */
export function middlewareCovers(infos: readonly MiddlewareInfo[], url: string | undefined): boolean {
  const probes = url === undefined ? ["/", "/x", "/x/y"] : [url];
  return infos.some((m) => {
    if (!m.authenticates) return false;
    if (m.matchers === "all") return true;
    const rx = m.matchers;
    return url === undefined ? probes.some((p) => rx.some((r) => r.test(p))) : rx.some((r) => r.test(url));
  });
}
