import type { Source } from "./lexer.js";
import { findRouteRegistrations } from "./routes.js";

export type FileKind = "route" | "pagesApi" | "action" | "middleware" | "express" | "client" | "other";

export interface Directives {
  readonly useClient: boolean;
  readonly useServer: boolean;
  /** Every directive string at the top of the file, in order. */
  readonly all: readonly string[];
}

const normalize = (p: string): string => p.replace(/\\/g, "/");

/** File-level directives: the string-literal statements at the very top (comments/BOM/blank lines skipped). */
export function fileDirectives(src: Source): Directives {
  const code = src.code;
  const all: string[] = [];
  const re = /\s*(["'])([^"'\n]*)\1[ \t]*;?/y;
  let at = code.charCodeAt(0) === 0xfeff ? 1 : 0;
  if (src.raw.startsWith("#!")) at = Math.max(at, code.indexOf("\n") + 1);
  for (;;) {
    re.lastIndex = at;
    const m = re.exec(code);
    if (!m) break;
    all.push(m[2] ?? "");
    at = re.lastIndex;
  }
  return { useClient: all.includes("use client"), useServer: all.includes("use server"), all };
}

const MIDDLEWARE_PATH = /^(?:(?:apps|packages)\/[^/]+\/)?(?:src\/)?(?:middleware|proxy)\.(?:ts|js|mjs|mts|cjs)$/;
const ROUTE_PATH = /(?:^|\/)app\/(?:.*\/)?route\.(?:ts|tsx|js|jsx|mjs)$|(?:^|\/)\+server\.[jt]s$/;
const PAGES_API_PATH = /(?:^|\/)pages\/api\//;
const SERVER_DIR = /(?:^|\/)(?:api|server|functions|actions|scripts|cli|backend|workers?)\/|\.server\.[jt]sx?$/;
const SERVER_IMPORT = /(?:from\s*|require\s*\(\s*)["'](?:express|fastify|next\/server|hono|koa|node:[\w/]+|fs|http|https|child_process)["']/;
const FRAMEWORK_IMPORT =
  /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:express|hono(?:\/[\w-]+)?|fastify|koa|@koa\/router|koa-router|@hapi\/hapi|restify|elysia|polka|h3)["']/;

/** Classification that needs only the path (middleware / route / pagesApi), else undefined. */
export function classifyPath(path: string): "middleware" | "route" | "pagesApi" | undefined {
  const p = normalize(path);
  if (MIDDLEWARE_PATH.test(p)) return "middleware";
  if (ROUTE_PATH.test(p)) return "route";
  if (PAGES_API_PATH.test(p)) return "pagesApi";
  return undefined;
}

export interface ClassifyOptions {
  /** The project is a Vite/CRA-style client app: non-server files under src/ count as "client". */
  readonly clientTree?: boolean;
}

/** Kind of a file, decided in this order: middleware, route, pagesApi, action, express, client, other. */
export function classifyFile(src: Source, options: ClassifyOptions = {}): FileKind {
  const byPath = classifyPath(src.path);
  if (byPath) return byPath;
  const dir = fileDirectives(src);
  if (dir.useServer) return "action";
  if (FRAMEWORK_IMPORT.test(src.code) && findRouteRegistrations(src).length > 0) return "express";
  if (dir.useClient) return "client";
  if (options.clientTree) {
    const p = normalize(src.path);
    const inSrc = /(?:^|\/)src\//.test(p) && /\.[jt]sx?$/.test(p);
    if (inSrc && !SERVER_DIR.test(p) && !SERVER_IMPORT.test(src.code)) return "client";
  }
  return "other";
}

/** True when the function body starts with an inline `"use server"` directive. */
export function hasInlineUseServer(src: Source, bodyStart: number): boolean {
  return /^\{\s*["']use server["']/.test(src.code.slice(bodyStart, bodyStart + 60));
}

const TEST_DIR = /(?:^|\/)(?:tests?|__tests__|__mocks__|__fixtures__|fixtures?|specs?|e2e)\//i;
const TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/i;

/** The single definition of "this is test code". */
export function isTestPath(path: string): boolean {
  const p = normalize(path);
  return TEST_DIR.test(p) || TEST_FILE.test(p);
}

const VENDOR = /(?:^|\/)(?:node_modules|vendor|third_party|bower_components|\.yarn|\.pnp)\//;
const GENERATED_DIR = /(?:^|\/)(?:dist|build|out|coverage|\.next|\.nuxt|\.svelte-kit|\.turbo|\.git|__generated__|generated)\//;
const GENERATED_FILE = /(?:\.d\.[cm]?ts|\.min\.[cm]?js|\.bundle\.js|\.generated\.[cm]?[jt]sx?|\.gen\.[cm]?[jt]sx?|-generated\.[jt]sx?)$/;

export function isVendorPath(path: string): boolean {
  return VENDOR.test(normalize(path));
}

export function isGeneratedPath(path: string): boolean {
  const p = normalize(path);
  return GENERATED_DIR.test(p) || GENERATED_FILE.test(p);
}

/** URL path implied by a Next.js route file or pages/api file; undefined for other files. */
export function routeFromPath(path: string): string | undefined {
  const p = normalize(path);
  const r = /(?:^|\/)app\/(?:(.*)\/)?route\.[a-z]+$/.exec(p);
  if (r) {
    const segs = (r[1] ?? "").split("/").filter((s) => s !== "" && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
    return `/${segs.join("/")}`;
  }
  const a = /(?:^|\/)pages\/(api(?:\/.*)?)\.[a-z]+$/.exec(p);
  if (a) return `/${(a[1] ?? "").replace(/\/index$/, "")}`;
  return undefined;
}
