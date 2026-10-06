import { matchClose } from "../../core/source/index.js";
import type { FileCtx, Project } from "./context.js";
import { middlewareCovers } from "./middleware.js";
import { isPagesApiPath, isRouteHandlerPath } from "./patterns.js";
import type { Raised } from "./report-types.js";
import { codeMatches, hasCode, makeHit } from "./util.js";

const REDIRECT =
  /\b(?:router|history|navigation)\.(?:push|replace)\s*\(|\bnavigate\s*\(|\bredirect\s*\(|window\.location|\blocation\.(?:href|assign|replace)/;
const LOGIN_TARGET = /["'`][^"'`\n]*(?:login|log-in|signin|sign-in|sign_in|auth|unauthori[sz]ed|signup)[^"'`\n]*["'`]/i;
const NOT_AUTHED =
  /!\s*(?:user|session|currentUser|isAuthenticated|isLoggedIn|isSignedIn|loggedIn|token|authUser)\b|\b(?:user|session|currentUser|token)\s*(?:===|==)\s*(?:null|undefined)|\b(?:status|authStatus)\s*===\s*["']unauthenticated["']|!\s*\w*(?:[Aa]uth|[Ll]ogged)\w*|isAuthenticated\s*===\s*false/;

/** AUTH-001: protected page redirects only from client code and nothing server-side backs it up. */
export function clientOnlyGuard(f: FileCtx, project: Project): Raised[] {
  if (project.hasServerAuth) return [];
  // No server handlers of its own (a Supabase/Firebase SPA, or an API in another repo): the browser redirect
  // guards nothing here; data protection is the database rules' job (DatabaseGuard). Public-repo study.
  if (!project.hasServerHandlers) return [];
  if (isRouteHandlerPath(f.path) || isPagesApiPath(f.path)) return [];
  if (middlewareCovers(project.middleware, f.url)) return [];
  const { src } = f;
  const confidence = project.hasUnguardedServerData ? "high" : "medium";
  for (const m of codeMatches(src, /\buseEffect\s*\(/)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close === -1) continue;
    const redirect = codeMatches(src, REDIRECT, open, close)[0];
    if (redirect && hasCode(src, NOT_AUTHED, open, close) && LOGIN_TARGET.test(src.code.slice(open, close))) {
      return [{ ...makeHit(src, "AUTH-001", redirect.index), confidence }];
    }
  }
  for (const m of codeMatches(src, /<Navigate\b[^>]*>/)) {
    if (!LOGIN_TARGET.test(m[0])) continue;
    const lineStart = src.code.lastIndexOf("\n", m.index - 1);
    const prevStart = src.code.lastIndexOf("\n", lineStart - 1);
    if (hasCode(src, NOT_AUTHED, prevStart + 1, m.index)) return [{ ...makeHit(src, "AUTH-001", m.index), confidence }];
  }
  return [];
}

const KEYS = String.raw`(?:isAdmin|is_admin|admin|isSuperAdmin|isStaff|role|userRole|user_role|plan|isPremium|isPro|is_pro|tier|subscription)`;
const STORAGE_READS = [
  new RegExp(String.raw`\b(?:localStorage|sessionStorage)\.getItem\(\s*(["'])${KEYS}\1\s*\)`),
  new RegExp(String.raw`\b(?:Cookies|cookies\(\)|(?:req|request)\.cookies|cookieStore|cookies)\.get\(\s*(["'])${KEYS}\1\s*\)`),
  new RegExp(
    String.raw`JSON\.parse\(\s*(?:localStorage|sessionStorage)\.getItem\([^)]*\)[^)]*\)\??\.(?:isAdmin|is_admin|role|plan|admin)\b`,
  ),
];
const CONDITION = /===|!==|==|!=|\bif\s*\(|&&|(?<!\?)\?(?![.?])/;

function lineBounds(code: string, index: number): [number, number] {
  const start = code.lastIndexOf("\n", index - 1) + 1;
  const end = code.indexOf("\n", index);
  return [start, end === -1 ? code.length : end];
}

/** Is `name` used as an access decision after `from`? Strings and comments never count. */
export function usedAsGate(f: FileCtx, name: string, from: number): boolean {
  const n = name.replace(/\$/g, String.raw`\$`);
  const gate = new RegExp(
    String.raw`\bif\s*\(\s*!?${n}\b|\b${n}\s*(?:===|!==|==|!=|&&|\|\||\?(?![.?]))|(?:===|!==|==|!=|&&)\s*${n}\b`,
  );
  return hasCode(f.src, gate, from);
}

/** AUTH-005: role/plan read from storage the user controls and used as an access decision. */
export function clientControlledRole(f: FileCtx): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  const seen = new Set<number>();
  for (const re of STORAGE_READS) {
    for (const m of codeMatches(src, re)) {
      const [start, end] = lineBounds(src.code, m.index);
      if (seen.has(start)) continue;
      const line = src.code.slice(start, end);
      const decl = /\b(?:const|let|var)\s+(\w+)\s*=/.exec(line);
      const gated = CONDITION.test(line) || (decl?.[1] !== undefined && usedAsGate(f, decl[1], end));
      if (!gated) continue;
      seen.add(start);
      out.push({ ...makeHit(src, "AUTH-005", m.index), confidence: "medium" });
    }
  }
  return out;
}

const PUBLIC_ENV_SERVICE = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_\w*SERVICE_ROLE\w*/;
const SERVICE = /SERVICE_ROLE|service_role/;
const SERVER_DIR = /(?:^|\/)(?:server|api|scripts|backend|functions|supabase\/functions)\//;

function clientContext(f: FileCtx, hasVite: boolean): "high" | "medium" | null {
  if (f.kind === "action") return null;
  const p = f.path;
  if (f.isClient) return "high";
  // Without "use client" a file under components/ is a server component unless a client file imports it.
  if (/(?:^|\/)(?:src\/)?components\//.test(p)) return "medium";
  if (/(?:^|\/)(?:src\/)?pages\//.test(p) && !isPagesApiPath(p)) {
    return /getServerSideProps|getStaticProps|getInitialProps/.test(f.src.code) ? null : "medium";
  }
  if (hasVite && p.startsWith("src/") && !SERVER_DIR.test(p)) return "medium";
  return null;
}

/** AUTH-007: Supabase service_role key reachable from browser code. */
export function serviceRoleInClient(f: FileCtx, project: Project): Raised[] {
  const exposed = codeMatches(f.src, PUBLIC_ENV_SERVICE)[0];
  if (exposed) return [{ ...makeHit(f.src, "AUTH-007", exposed.index), confidence: "high" }];
  const confidence = clientContext(f, project.hasVite);
  if (!confidence) return [];
  const hit = codeMatches(f.src, SERVICE)[0];
  return hit ? [{ ...makeHit(f.src, "AUTH-007", hit.index), confidence }] : [];
}
