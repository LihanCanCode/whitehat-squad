import type { Source } from "./lexer.js";
import { readFunctionAt } from "./functions.js";
import { matchClose, matchOpen, splitArgs } from "./scan.js";
import type { Span } from "./scan.js";

export interface RouteRegistration {
  /** Last identifier of the receiver chain, e.g. "app", "router", "api". */
  readonly receiver: string;
  /** Lower-case verb: get/post/put/patch/delete/all/use/head/options. */
  readonly method: string;
  /** Path literal of the first argument (or of `.route('/x')`), when static. */
  readonly route?: string;
  /** Start of the receiver expression. */
  readonly start: number;
  /** Offset of the call's `(`. */
  readonly open: number;
  /** Exclusive end (just past `)`). */
  readonly end: number;
  readonly args: readonly Span[];
  /** Index into `args` of the handler (last function arg, else last identifier arg), or -1. */
  readonly handlerArg: number;
  /** Indices of the other non-path arguments (middleware). */
  readonly middlewareArgs: readonly number[];
}

const VERB_CALL = /\.\s*(get|post|put|patch|delete|all|use|head|options)\s*\(/g;
const ROUTER_NAME = /^(?:app|router|server|fastify|api|routes?|hono|koa|express|r|v\d+|\w*(?:App|Router|Server|Routes?|Hono|Koa|Fastify|Api))$/;
const ROUTER_CTOR = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:new\s+)?(?:express(?:\s*\.\s*Router)?|Router|KoaRouter|Hono|Fastify|fastify|Koa|Elysia)\s*[(<]/g;

const VERBS = new Set(["get", "post", "put", "patch", "delete", "all", "use", "head", "options"]);

const cache = new WeakMap<Source, readonly RouteRegistration[]>();

function isIdentChar(c: string): boolean {
  return /[\w$]/.test(c);
}

interface Receiver {
  readonly root: string;
  readonly last: string;
  readonly start: number;
  readonly routePath?: string;
}

function readIdentBack(b: string, end: number): { name: string; start: number } {
  let s = end;
  while (s > 0 && isIdentChar(b.charAt(s - 1))) s--;
  return { name: b.slice(s, end), start: s };
}

function skipWsBack(b: string, i: number): number {
  let j = i;
  while (j > 0 && /\s/.test(b.charAt(j - 1))) j--;
  return j;
}

/** Walks back from the `.` before a verb through `.name` and `.call(...)` segments to the chain root. */
function receiverOf(src: Source, dot: number, routePathOf: (open: number) => string | undefined): Receiver | null {
  const b = src.bare;
  let j = skipWsBack(b, dot);
  let last = "";
  let routePath: string | undefined;
  let chainedVerb = false;
  for (let guard = 0; guard < 40; guard++) {
    if (b.charAt(j - 1) === ")") {
      const open = matchOpen(src, j - 1);
      if (open < 0) return null;
      const callee = readIdentBack(b, skipWsBack(b, open));
      if (callee.name === "") return null;
      if (callee.name === "route" && routePath === undefined) routePath = routePathOf(open);
      if (last === "") {
        last = callee.name;
        chainedVerb = VERBS.has(callee.name);
      }
      j = skipWsBack(b, callee.start);
      if (b.charAt(j - 1) === ".") {
        j = skipWsBack(b, j - 1);
        continue;
      }
      return { root: callee.name, last, start: chainedVerb ? dot : callee.start, routePath };
    }
    const id = readIdentBack(b, j);
    if (id.name === "") return null;
    if (last === "") last = id.name;
    j = skipWsBack(b, id.start);
    if (b.charAt(j - 1) === ".") {
      j = skipWsBack(b, j - 1);
      continue;
    }
    return { root: id.name, last, start: chainedVerb ? dot : id.start, routePath };
  }
  return null;
}

function staticPath(src: Source, span: Span): string | undefined {
  const c = src.bare.charAt(span.start);
  if (c === '"' || c === "'") return src.code.slice(span.start + 1, span.end - 1);
  if (c === "`") {
    const body = src.code.slice(span.start + 1, span.end - 1);
    return body;
  }
  if (c === "/") return src.code.slice(span.start, span.end);
  return undefined;
}

function isPathLike(src: Source, span: Span): boolean {
  return /["'`/\[]/.test(src.bare.charAt(span.start));
}

export function findRouteRegistrations(src: Source): readonly RouteRegistration[] {
  const cached = cache.get(src);
  if (cached) return cached;
  const b = src.bare;
  const routerVars = new Set<string>();
  for (const m of b.matchAll(ROUTER_CTOR)) if (m[1]) routerVars.add(m[1]);
  const out: RouteRegistration[] = [];
  const re = new RegExp(VERB_CALL.source, "g");
  for (let m = re.exec(b); m; m = re.exec(b)) {
    const dot = m.index;
    const open = dot + m[0].length - 1;
    const close = matchClose(src, open);
    if (close < 0) continue;
    const routePathOf = (o: number): string | undefined => {
      const c = matchClose(src, o);
      const first = c < 0 ? undefined : splitArgs(src, o + 1, c - 1)[0];
      return first ? staticPath(src, first) : undefined;
    };
    const recv = receiverOf(src, dot, routePathOf);
    if (!recv) continue;
    if (!(ROUTER_NAME.test(recv.root) || ROUTER_NAME.test(recv.last) || routerVars.has(recv.root) || routerVars.has(recv.last))) continue;
    const method = (m[1] ?? "").toLowerCase();
    const args = splitArgs(src, open + 1, close - 1);
    if (args.length === 0) continue;
    const first = args[0];
    const pathArg = recv.routePath === undefined && first && isPathLike(src, first) && args.length > 1 ? 1 : 0;
    const hasPathArg = recv.routePath === undefined && pathArg === 1;
    if (method !== "use" && !recv.routePath && !(hasPathArg || args.length >= 2)) continue;
    if (method !== "use" && recv.routePath === undefined && args.length < 2) continue;
    const firstHandler = hasPathArg ? 1 : 0;
    let handlerArg = -1;
    const middleware: number[] = [];
    for (let k = args.length - 1; k >= firstHandler; k--) {
      const a = args[k];
      if (a && readFunctionAt(src, a.start)) {
        handlerArg = k;
        break;
      }
    }
    if (handlerArg < 0) {
      for (let k = args.length - 1; k >= firstHandler; k--) {
        const a = args[k];
        if (a && /^[A-Za-z_$][\w$]*$/.test(b.slice(a.start, a.end))) {
          handlerArg = k;
          break;
        }
      }
    }
    for (let k = firstHandler; k < args.length; k++) if (k !== handlerArg) middleware.push(k);
    const route = recv.routePath ?? (hasPathArg && first ? staticPath(src, first) : method === "use" && first ? staticPath(src, first) : undefined);
    out.push({
      receiver: recv.last,
      method,
      route,
      start: recv.start,
      open,
      end: close,
      args,
      handlerArg,
      middlewareArgs: middleware,
    });
  }
  cache.set(src, out);
  return out;
}
