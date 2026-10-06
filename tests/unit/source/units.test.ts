import { describe, expect, it } from "vitest";
import { findUnits, handlerUnits, unitAt, unitBody } from "../../../src/core/source/units.js";
import { matchClose, splitArgs, exprEnd } from "../../../src/core/source/scan.js";
import { findRouteRegistrations } from "../../../src/core/source/routes.js";
import {
  ACTIONS,
  ACTIONS_PATH,
  EXPRESS_APP,
  EXPRESS_PATH,
  INLINE_ACTION,
  INLINE_ACTION_PATH,
  NEXT_ROUTE,
  NEXT_ROUTE_PATH,
  src,
} from "./fixtures.js";

const names = (units: ReadonlyArray<{ name: string }>) => units.map((u) => u.name);

describe("scan helpers", () => {
  const s = src("a.ts", "f(a, [1, 2], { x: `a,${g(1, 2)}` }, (b, c) => b)");
  it("matchClose pairs brackets of every kind and ignores strings", () => {
    const open = s.bare.indexOf("(");
    expect(matchClose(s, open)).toBe(s.bare.length);
    expect(matchClose(s, 0)).toBe(-1);
    expect(matchClose(s, 9999)).toBe(-1);
  });
  it("splitArgs splits at top-level commas only", () => {
    const open = s.bare.indexOf("(");
    const args = splitArgs(s, open + 1, matchClose(s, open) - 1).map((a) => s.raw.slice(a.start, a.end));
    expect(args).toEqual(["a", "[1, 2]", "{ x: `a,${g(1, 2)}` }", "(b, c) => b"]);
  });
  it("exprEnd stops at ; , or closing bracket and follows multi-line continuations", () => {
    const t = src("a.ts", "const a = b\n  .c()\n  + d;\nconst z = 1");
    const start = t.bare.indexOf("b");
    expect(t.raw.slice(start, exprEnd(t, start))).toBe("b\n  .c()\n  + d");
    const u = src("a.ts", "x = 1\ny = 2");
    expect(exprEnd(u, 4)).toBe(5);
    const w = src("a.ts", "f(a => a.b, 2)");
    expect(w.raw.slice(2, exprEnd(w, 2))).toBe("a => a.b");
  });
});

describe("findUnits: declarations", () => {
  it("finds function declarations (plain, async, export, export default, generics, return types)", () => {
    const s = src(
      "lib.ts",
      `function a(x: number) { return x; }
export async function b<T extends object>(y: T): Promise<{ ok: boolean }> { return { ok: true }; }
export default function c(z) {}
async function* gen() {}
function overload(a: string): void;
function overload(a: string | number): void {}
`,
    );
    const units = findUnits(s);
    expect(names(units)).toEqual(expect.arrayContaining(["a", "b", "c", "gen", "overload"]));
    const b = units.find((u) => u.name === "b")!;
    expect(b.exported).toBe(true);
    expect(b.kind).toBe("function");
    expect(b.params).toBe("y: T");
    expect(s.raw[b.bodyStart]).toBe("{");
    expect(s.raw.slice(b.start, b.start + 15)).toBe("export async fu");
    expect(units.find((u) => u.name === "a")!.exported).toBe(false);
    expect(units.filter((u) => u.name === "overload")).toHaveLength(1);
    const c = units.find((u) => u.name === "c")!;
    expect(c.exported).toBe(true);
    expect(c.exportedAs).toContain("default");
  });

  it("finds arrows and function expressions bound to const/let/var, block and expression bodied", () => {
    const s = src(
      "lib.ts",
      `export const a = async (x: string, y = f(1)): Promise<void> => { await x; };
const b = (x) => x + 1;
let c = x => x.y
  .z();
var d = function named(p) { return p; };
const e: Handler = async function () {};
const f = <T,>(x: T): T => x;
const notFn = 5;
`,
    );
    const units = findUnits(s);
    const by = (n: string) => units.find((u) => u.name === n)!;
    expect(names(units).sort()).toEqual(["a", "b", "c", "d", "e", "f"]);
    expect(by("a").kind).toBe("arrow");
    expect(by("a").exported).toBe(true);
    expect(by("a").params).toBe("x: string, y = f(1)");
    expect(s.raw.slice(by("b").bodyStart, by("b").end)).toBe("x + 1");
    expect(by("c").params).toBe("x");
    expect(s.raw.slice(by("c").bodyStart, by("c").end).replace(/\s+/g, "")).toBe("x.y.z()");
    expect(by("d").kind).toBe("function");
    expect(by("e").kind).toBe("function");
  });

  it("detects export lists, aliases and CommonJS exports", () => {
    const s = src(
      "lib.js",
      `function a() {}
const b = () => {};
function c() {}
export { a, b as renamed };
module.exports = { c };
`,
    );
    const units = findUnits(s);
    expect(units.find((u) => u.name === "a")!.exported).toBe(true);
    const b = units.find((u) => u.name === "b")!;
    expect(b.exported).toBe(true);
    expect(b.exportedAs).toContain("renamed");
    expect(units.find((u) => u.name === "c")!.exported).toBe(true);
  });

  it("finds exports.x = fn and module.exports = fn", () => {
    const s = src("lib.js", "exports.handler = async (event) => { return event; };\nmodule.exports = function (req, res) {};\n");
    const units = findUnits(s);
    expect(units.find((u) => u.name === "handler")?.exported).toBe(true);
    expect(units.find((u) => u.name === "default")?.exported).toBe(true);
  });

  it("finds class and object methods but not control flow or calls", () => {
    const s = src(
      "svc.ts",
      `class Svc {
  constructor(private a: string) {}
  async load(id: string): Promise<void> { if (id) { await this.x(id); } }
  static make() { return new Svc("a"); }
}
const o = { run(a) { for (const x of a) { while (x) { break; } } }, other: 1 };
`,
    );
    const units = findUnits(s);
    const methods = units.filter((u) => u.kind === "method").map((u) => u.name);
    expect(methods).toEqual(expect.arrayContaining(["constructor", "load", "make", "run"]));
    expect(methods).not.toContain("if");
    expect(methods).not.toContain("for");
    expect(methods).not.toContain("while");
  });

  it("ignores function-looking text in comments, strings, regexes and templates", () => {
    const s = src(
      "lib.ts",
      "// function ghost() {}\nconst a = 'function ghost2() {}';\nconst b = /function ghost3() {}/;\nconst c = `function ghost4() {}`;\n/* export const ghost5 = () => {} */\nfunction real() {}",
    );
    expect(names(findUnits(s))).toEqual(["real"]);
  });

  it("is robust when strings or regexes contain braces", () => {
    const s = src("lib.ts", "function a() { const s = '}'; const r = /[}]/; const t = `}${'{'}`; return 1; }\nfunction b() {}\n");
    const units = findUnits(s);
    const a = units.find((u) => u.name === "a")!;
    expect(s.raw.slice(a.end - 1, a.end)).toBe("}");
    expect(s.raw.slice(a.end).trim().startsWith("function b")).toBe(true);
  });

  it("returns units sorted by start and caches per source", () => {
    const s = src("lib.ts", "function b() {}\nfunction a() {}");
    const u = findUnits(s);
    expect(u.map((x) => x.start)).toEqual([...u.map((x) => x.start)].sort((x, y) => x - y));
    expect(findUnits(s)).toBe(u);
  });

  it("unitAt returns the innermost unit and unitBody the code text", () => {
    const s = src("lib.ts", "function outer() { const inner = () => { return 1; }; return inner; }");
    const units = findUnits(s);
    const at = s.raw.indexOf("return 1");
    expect(unitAt(units, at)?.name).toBe("inner");
    expect(unitAt(units, s.raw.indexOf("return inner"))?.name).toBe("outer");
    expect(unitAt(units, 0)?.name).toBe("outer");
    expect(unitAt([], 3)).toBeUndefined();
    expect(unitBody(s, units.find((u) => u.name === "inner")!).code).toContain("return 1");
  });

  it("copes with empty and malformed input", () => {
    expect(findUnits(src("a.ts", ""))).toEqual([]);
    expect(() => findUnits(src("a.ts", "function (( { => const = export default"))).not.toThrow();
    expect(() => findUnits(src("a.ts", "app.get(("))).not.toThrow();
  });
});

describe("handlerUnits: Next.js route files", () => {
  const s = src(NEXT_ROUTE_PATH, NEXT_ROUTE);
  const hs = handlerUnits(s);
  it("returns exactly the HTTP method exports, as handler units with a route", () => {
    expect(hs.map((h) => h.httpMethod).sort()).toEqual(["DELETE", "GET", "POST"]);
    for (const h of hs) {
      expect(h.kind).toBe("handler");
      expect(h.exported).toBe(true);
      expect(h.route).toBe("/api/projects/[id]");
      expect(h.role).toBe("route");
    }
    expect(names(hs).sort()).toEqual(["DELETE", "GET", "POST"]);
  });
  it("covers the whole body of each handler and reports params", () => {
    const get = hs.find((h) => h.httpMethod === "GET")!;
    const text = s.raw.slice(get.start, get.end);
    expect(text).toContain("getUser");
    expect(text).not.toContain("POST");
    expect(get.params).toContain("{ params }");
    const del = hs.find((h) => h.httpMethod === "DELETE")!;
    expect(s.raw.slice(del.start, del.end)).toContain("db.project.delete");
    expect(s.raw.slice(del.start, del.end)).not.toContain("helper");
  });
  it("supports export { handler as GET, handler as POST } and export const GET = handler", () => {
    const t = src(
      "app/x/route.ts",
      "async function handler(req: Request) { return new Response('ok'); }\nasync function other(req: Request) {}\nexport { handler as GET, handler as POST };\nexport const PUT = other;\n",
    );
    const h = handlerUnits(t);
    expect(h.map((u) => u.httpMethod).sort()).toEqual(["GET", "POST", "PUT"]);
    expect(h.filter((u) => u.httpMethod === "GET" || u.httpMethod === "POST").every((u) => u.params === "req: Request")).toBe(true);
  });
  it("supports wrapper calls: export const POST = withAuth(async (req) => {...})", () => {
    const t = src("app/y/route.ts", "export const POST = withAuth(async (req, { user }) => {\n  return Response.json(user);\n});\nexport const GET = withAuth(list);\nasync function list(req) {}\n");
    const h = handlerUnits(t);
    const post = h.find((u) => u.httpMethod === "POST")!;
    expect(post.params).toBe("req, { user }");
    expect(t.raw.slice(post.start, post.end)).toContain("withAuth");
    const get = h.find((u) => u.httpMethod === "GET")!;
    expect(get.extraRanges?.length).toBeGreaterThan(0);
  });
  it("does not treat non-HTTP exports as handlers", () => {
    const t = src("app/z/route.ts", "export const dynamic = 'force-dynamic';\nexport async function GET() {}\nexport function helper() {}\nexport const runtime = 'edge';\n");
    expect(handlerUnits(t).map((u) => u.name)).toEqual(["GET"]);
  });
});

describe("handlerUnits: pages/api, middleware, actions", () => {
  it("pages/api default export (function, reference, wrapper)", () => {
    const a = handlerUnits(src("pages/api/items/[id].ts", "export default async function handler(req, res) { res.end(); }"));
    expect(a).toHaveLength(1);
    expect(a[0]).toMatchObject({ name: "handler", kind: "handler", role: "pagesApi", route: "/api/items/[id]", exported: true });
    const b = handlerUnits(src("pages/api/a.js", "async function handler(req, res) {}\nexport default handler;\n"));
    expect(b.map((u) => u.name)).toEqual(["handler"]);
    const c = handlerUnits(src("pages/api/b.js", "async function handler(req, res) {}\nexport default withAuth(handler);\n"));
    expect(c).toHaveLength(1);
    expect(c[0]?.params).toBe("req, res");
    expect(c[0]?.extraRanges?.length).toBeGreaterThan(0);
    const d = handlerUnits(src("pages/api/c.js", "export default (req, res) => { res.end(); };"));
    expect(d[0]?.params).toBe("req, res");
  });

  it("middleware files", () => {
    const m = handlerUnits(src("src/middleware.ts", "export function middleware(req: NextRequest) { return NextResponse.next(); }\nexport const config = { matcher: ['/a'] };"));
    expect(m.map((u) => [u.name, u.role])).toEqual([["middleware", "middleware"]]);
    const p = handlerUnits(src("proxy.ts", "export default async function proxy(req) {}"));
    expect(p[0]?.role).toBe("middleware");
    const q = handlerUnits(src("middleware.ts", "export default auth((req) => { return null; });"));
    expect(q).toHaveLength(1);
  });

  it("server action files: every exported function is an action, helpers are not", () => {
    const s = src(ACTIONS_PATH, ACTIONS);
    const units = findUnits(s);
    const actions = units.filter((u) => u.action);
    expect(names(actions).sort()).toEqual(["deleteAccount", "updateProfile"]);
    expect(handlerUnits(s).map((u) => u.name).sort()).toEqual(["deleteAccount", "updateProfile"]);
    expect(units.find((u) => u.name === "internalHelper")?.action).toBeFalsy();
    expect(actions.every((u) => u.role === "action")).toBe(true);
  });

  it("inline 'use server' functions inside other files", () => {
    const s = src(INLINE_ACTION_PATH, INLINE_ACTION);
    const units = findUnits(s);
    expect(units.find((u) => u.name === "save")?.action).toBe(true);
    expect(units.find((u) => u.name === "Page")?.action).toBeFalsy();
    expect(handlerUnits(s).map((u) => u.name)).toEqual(["save"]);
  });

  it("plain library files have no handler units", () => {
    expect(handlerUnits(src("src/lib/a.ts", "export function a() {}\nexport const b = () => {};"))).toEqual([]);
  });
});

describe("route registrations and handler units: Express/Hono/Fastify/Koa", () => {
  const s = src(EXPRESS_PATH, EXPRESS_APP);
  it("finds app/router verbs and ignores non-routers", () => {
    const regs = findRouteRegistrations(s);
    expect(regs.map((r) => `${r.method} ${r.route ?? ""}`)).toEqual(["use ", "get /users/:id", "post /notes", "delete /files/:name"]);
    expect(regs[2]?.args).toHaveLength(4);
    expect(regs[2]?.middlewareArgs).toHaveLength(2);
    expect(regs[0]?.handlerArg).toBe(-1);
  });
  it("makes the last function argument the handler and keeps middleware in range", () => {
    const hs = handlerUnits(s);
    expect(hs.map((h) => h.httpMethod)).toEqual(["GET", "POST", "DELETE"]);
    const post = hs[1]!;
    expect(post.kind).toBe("handler");
    expect(post.route).toBe("/notes");
    expect(post.params).toBe("req, res");
    expect(s.raw.slice(post.start, post.end)).toContain("authMiddleware");
    expect(s.raw.slice(post.start, post.end)).toContain("rateLimit");
    expect(s.raw[post.bodyStart]).toBe("{");
    expect(post.receiver).toBe("app");
    const del = hs[2]!;
    expect(del.params).toBe("req, res");
    expect(del.receiver).toBe("router");
    expect(s.raw.slice(del.start, del.end)).not.toContain("listen");
  });
  it("resolves identifier handlers to the named function and keeps the registration as an extra range", () => {
    const t = src("app.js", "const app = require('express')();\nfunction list(req, res) { res.json([]); }\napp.get('/l', requireAuth, list);\n");
    const h = handlerUnits(t)[0]!;
    expect(h.name).toBe("list");
    expect(h.params).toBe("req, res");
    expect(t.raw.slice(h.start, h.end)).toContain("res.json");
    expect(h.extraRanges).toHaveLength(1);
    const range = h.extraRanges![0]!;
    expect(t.raw.slice(range.start, range.end)).toContain("requireAuth");
  });
  it("keeps unresolved (imported) handlers as units covering the registration", () => {
    const t = src("app.js", "const app = express();\napp.post('/p', requireAuth, ctrl.create);\n");
    const hs = handlerUnits(t);
    expect(hs).toHaveLength(1);
    expect(t.raw.slice(hs[0]!.start, hs[0]!.end)).toContain("requireAuth");
  });
  it("supports Hono, Fastify, Koa, chained and nested registration", () => {
    const hono = src("a.ts", "import { Hono } from 'hono';\nconst api = new Hono();\napi.get('/a', (c) => c.json(1)).post('/b', async (c) => { return c.text('x'); });\n");
    expect(handlerUnits(hono).map((h) => `${h.httpMethod} ${h.route}`)).toEqual(["GET /a", "POST /b"]);
    const fastify = src("a.js", "const fastify = require('fastify')();\nfastify.post('/x', { schema: {} }, async (request, reply) => { return {}; });\n");
    expect(handlerUnits(fastify)[0]?.params).toBe("request, reply");
    const koa = src("a.js", "const Router = require('koa-router');\nconst r = new Router();\nr.get('/k', async (ctx, next) => { ctx.body = 1; });\n");
    expect(handlerUnits(koa)[0]?.params).toBe("ctx, next");
    const nested = src("routes.js", "module.exports = function register(app) {\n  app.get('/n', (req, res) => { res.send(1); });\n};\n");
    const hs = handlerUnits(nested);
    expect(hs).toHaveLength(1);
    expect(unitAt(findUnits(nested), nested.raw.indexOf("res.send"))?.kind).toBe("handler");
    const route = src("a.js", "const router = express.Router();\nrouter.route('/r').get(list).post(auth, create);\nfunction list() {}\nfunction create() {}\n");
    expect(handlerUnits(route).map((h) => `${h.httpMethod} ${h.route}`)).toEqual(["GET /r", "POST /r"]);
  });
  it("does not confuse Map/URLSearchParams/axios .get with route registration", () => {
    const t = src("a.ts", "const m = new Map();\nm.get('a');\nconst v = params.get('x', 1);\naxios.get('/a', (x) => x);\nsearchParams.get('q');");
    expect(findRouteRegistrations(t)).toEqual([]);
  });
  it("app.use with a function becomes a handler unit; app.use(cors()) does not", () => {
    const t = src("a.js", "const app = express();\napp.use(cors());\napp.use('/admin', (req, res, next) => { next(); });\n");
    const hs = handlerUnits(t);
    expect(hs).toHaveLength(1);
    expect(hs[0]?.httpMethod).toBe("USE");
    expect(hs[0]?.route).toBe("/admin");
  });
});
