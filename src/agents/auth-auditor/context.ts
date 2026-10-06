import {
  AUTH_CHECK, classifyFile, createSource, exprEnd, fileDirectives, findUnits, guardMatches, handlerUnits, parseBindingNames,
  type FileKind, type FunctionUnit, type Source,
} from "../../core/source/index.js";
import type { MiddlewareInfo } from "./middleware.js";
import { urlOfFile } from "./patterns.js";
import { codeMatches, escapeRe } from "./util.js";

/** Everything a rule needs to know about one scanned file. */
export interface FileCtx {
  readonly src: Source;
  readonly path: string;
  readonly kind: FileKind;
  readonly isClient: boolean;
  /** Code that runs on the server (route, action, pages/api, middleware, Express, or server-only imports). */
  readonly isServer: boolean;
  readonly units: readonly FunctionUnit[];
  /** Request handlers and Server Actions (Next middleware excluded). */
  readonly handlers: readonly FunctionUnit[];
  /** Next.js URL of this file when it is a page or route. */
  readonly url: string | undefined;
}

/** Facts about the whole project that individual rules consult. */
export interface Project {
  readonly hasVite: boolean;
  readonly middleware: readonly MiddlewareInfo[];
  /** Some middleware rate limits requests. */
  readonly hasMiddlewareRateLimit: boolean;
  /** An auth provider (NextAuth, Clerk, Supabase, ...) is wired in, so built-in protections may apply. */
  readonly hasAuthProvider: boolean;
  /** Server-side code performs session checks. */
  hasServerAuth: boolean;
  /** Some server handler touches data with no session check. */
  hasUnguardedServerData: boolean;
  /** The repo has its own server request handlers (routes, actions, Express...). */
  readonly hasServerHandlers: boolean;
  /** Model/table names that have privilege-bearing columns (role, is_admin, credits...). */
  readonly sensitiveTargets: ReadonlySet<string>;
}

const SERVER_MARKERS = /["'](?:next\/headers|@supabase\/ssr|next-auth(?:\/[\w-]+)?|server-only|next\/server)["']|\bgetServerSideProps\b/;

export function buildFileCtx(path: string, raw: string, clientTree: boolean): FileCtx {
  const src = createSource(path, raw);
  const kind = classifyFile(src, { clientTree });
  const isClient = fileDirectives(src).useClient;
  const serverKinds: readonly FileKind[] = ["route", "pagesApi", "action", "middleware", "express"];
  const isServer = !isClient && (serverKinds.includes(kind) || SERVER_MARKERS.test(src.code));
  const units = findUnits(src);
  const handlers = handlerUnits(src).filter((u) => u.role !== "middleware");
  return { src, path, kind, isClient, isServer, units, handlers, url: urlOfFile(path) };
}

export function skipWs(s: string, i: number): number {
  let j = i;
  while (j < s.length && /\s/.test(s.charAt(j))) j++;
  return j;
}

const DECL = /\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])/g;

/** Names declared in `unit` from an auth call (`const { user } = await supabase.auth.getUser()`). */
export function authNames(f: FileCtx, unit: FunctionUnit): string[] {
  const { src } = f;
  const names = new Set<string>();
  const rx = new RegExp(DECL.source, "g");
  rx.lastIndex = unit.start;
  for (let m = rx.exec(src.bare); m && m.index < unit.end; m = rx.exec(src.bare)) {
    const rhsStart = skipWs(src.bare, m.index + m[0].length);
    const text = src.code.slice(rhsStart, exprEnd(src, rhsStart, true));
    if (AUTH_CHECK.test(text)) for (const n of parseBindingNames(m[1] ?? "")) names.add(n);
  }
  return [...names];
}

export const NEXT_AUTH_PROVIDER = /["'](?:next-auth|@auth\/core|@clerk\/[\w-]+|@supabase\/(?:ssr|supabase-js|auth-helpers-[\w-]+)|better-auth|lucia|@kinde-oss\/[\w-]+|@auth0\/[\w-]+|firebase\/auth|firebase-admin\/auth)(?:\/[\w./-]+)?["']/;

export function usesAuthProvider(files: readonly FileCtx[]): boolean {
  return files.some((f) => codeMatches(f.src, NEXT_AUTH_PROVIDER).length > 0);
}

/**
 * Does `unit` call a function declared in the same file whose own body has `guard` evidence?
 * (One level of inlining: `if (!(await verifyCurrentUserHasAccessToPost(id)))` where the helper calls getServerSession.)
 */
export function callsGuardedHelper(f: FileCtx, unit: FunctionUnit, guard: "auth" | "ownership"): boolean {
  const body = f.src.bare.slice(unit.start, unit.end);
  for (const h of f.units) {
    if (h === unit || h.kind === "handler" || h.name === "" || h.name === "default" || (h.start >= unit.start && h.end <= unit.end)) continue;
    if (!new RegExp(String.raw`(?<![\w$.])${escapeRe(h.name)}\s*\(`).test(body)) continue;
    if (guardMatches(f.src, h, guard).length > 0) return true;
  }
  return false;
}
