import { describe, expect, it } from "vitest";
import { analyzeTaint, REQUEST_SOURCES } from "../../../src/core/source/taint.js";
import { createSource } from "../../../src/core/source/lexer.js";
import { findUnits, handlerUnits } from "../../../src/core/source/units.js";
import { parseBindingNames, parseParams, splitTopLevel } from "../../../src/core/source/bindings.js";
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

/** Analyzes the first unit named `name` (or the only handler) of a snippet. */
function analyze(raw: string, name = "h", path = "app/api/x/route.ts", spec?: Parameters<typeof analyzeTaint>[2]) {
  const s = src(path, raw);
  const unit = findUnits(s).find((u) => u.name === name)!;
  return analyzeTaint(s, unit, spec);
}
const wrap = (body: string, params = "req") => `function h(${params}) {\n${body}\n}`;

describe("bindings", () => {
  it.each([
    ["a", ["a"]],
    ["{ a, b }", ["a", "b"]],
    ["{ a: x, b: { c, d: y }, ...rest }", ["x", "c", "y", "rest"]],
    ["{ a = 1, b: c = f(1, 2) }", ["a", "c"]],
    ["{ a = cond ? x : y }", ["a"]],
    ["[a, , b = 1, [c], ...d]", ["a", "b", "c", "d"]],
    ["{ data: { user } }: Props", ["user"]],
    ["{ [key]: v }", ["v"]],
    ["", []],
    ["  ", []],
    ["{ f = (a) => a }", ["f"]],
  ])("parseBindingNames(%s)", (p, names) => expect(parseBindingNames(p)).toEqual(names));

  it("splitTopLevel respects generics, brackets and strings", () => {
    expect(splitTopLevel("a: Map<string, number>, b = [1, 2], c = ','")).toHaveLength(3);
  });

  it("parseParams handles types, modifiers, rest and destructuring", () => {
    const p = parseParams("req: Request, { params }: { params: Promise<{ id: string }> }, ...rest: string[], private x = 1, this: Foo");
    expect(p.map((x) => x.names)).toEqual([["req"], ["params"], ["rest"], ["x"]]);
    expect(p[1]?.destructured).toBe(true);
  });
});

describe("analyzeTaint: sources catalog", () => {
  it("exports a catalog with ids and labels", () => {
    expect(REQUEST_SOURCES.length).toBeGreaterThan(8);
    for (const s of REQUEST_SOURCES) {
      expect(s.id).toBeTruthy();
      expect(s.re).toBeInstanceOf(RegExp);
    }
  });

  const direct: Array<[string, string]> = [
    ["req.body", "req.body.id"],
    ["req.query", "req.query.q"],
    ["req.params", "req.params.id"],
    ["req.headers", "req.headers['x-host']"],
    ["req.cookies", "req.cookies.sid"],
    ["request.json()", "await request.json()"],
    ["request.formData()", "(await request.formData()).get('a')"],
    ["request.text()", "await request.text()"],
    ["searchParams.get", "url.searchParams.get('q')"],
    ["nextUrl", "request.nextUrl.searchParams.get('q')"],
    ["hono c.req.json()", "await c.req.json()"],
    ["hono c.req.param()", "c.req.param('id')"],
    ["hono c.req.query()", "c.req.query('q')"],
    ["koa ctx.request.body", "ctx.request.body.name"],
    ["koa ctx.query", "ctx.query.q"],
    ["formData.get", "formData.get('x')"],
    ["next headers()", "(await headers()).get('host')"],
    ["h3 getQuery", "getQuery(event)"],
    ["lambda event.body", "JSON.parse(event.body)"],
  ];
  it.each(direct)("%s is a source", (_n, expr) => {
    const t = analyze(wrap("", "x"), "h");
    expect(t.isTainted(expr)).toBe(true);
  });

  const clean: Array<[string, string]> = [
    ["literal", "'abc'"],
    ["number", "42"],
    ["unrelated call", "getUserById(1)"],
    ["body in string only", "'req.body'"],
    ["body in comment", "x /* req.body */"],
    ["request.headers lookalike prop", "foo.request.header"],
    ["property of unrelated object", "config.body"],
  ];
  it.each(clean)("%s is not tainted", (_n, expr) => {
    const t = analyze(wrap("", "x"), "h");
    expect(t.isTainted(expr)).toBe(false);
  });

  it("supports caller-supplied extra sources (regex and string) and names", () => {
    const t = analyze(wrap("const a = getInput();\nconst b = other;"), "h", "lib.ts", { extraSources: [/\bgetInput\s*\(/, "window.location.hash"], taintedNames: ["other"] });
    expect(t.isTainted("a")).toBe(true);
    expect(t.isTainted("b")).toBe(true);
    expect(t.isTainted("window.location.hash")).toBe(true);
    expect(t.isTainted("window.location.href")).toBe(false);
  });
});

describe("analyzeTaint: propagation", () => {
  const cases: Array<[string, string, string[], string[]]> = [
    ["const", "const a = req.body.id;", ["a"], []],
    ["let + reassign", "let a = 'x';\na = req.query.q;", ["a"], []],
    ["destructure", "const { id, name } = req.body;", ["id", "name"], []],
    ["destructure rename", "const { id: userId } = req.body;", ["userId"], ["id"]],
    ["destructure nested + rename", "const { data: { user: u, tags = [] }, ...others } = req.body;", ["u", "tags", "others"], ["data", "user"]],
    ["array destructure", "const [first, , third] = req.body.items;", ["first", "third"], []],
    ["spread object", "const a = { ...req.body, extra: 1 };", ["a"], []],
    ["spread array", "const a = [...req.body.ids, 1];", ["a"], []],
    ["template", "const a = `x-${req.params.id}`;", ["a"], []],
    ["concat", "const t = req.query.q;\nconst s = 'select ' + t + ' from x';", ["t", "s"], []],
    ["await", "const a = await req.json();", ["a"], []],
    ["member access", "const q = req.query;\nconst id = q.id;\nconst n = q.nested.deep;", ["q", "id", "n"], []],
    ["String() / trim() keep taint", "const t = req.body.t;\nconst a = String(t);\nconst b = t.trim().toLowerCase();", ["a", "b"], []],
    ["JSON.parse keeps taint", "const a = JSON.parse(req.body.raw);", ["a"], []],
    ["path.join keeps taint", "const f = path.join('/srv', req.query.file);", ["f"], []],
    ["ternary / ||", "const a = ok ? req.query.a : 'x';\nconst b = req.query.b || 'dflt';", ["a", "b"], []],
    ["object literal containing tainted", "const o = { id: req.params.id, ok: true };", ["o"], []],
    ["member write taints the object", "const data = {};\ndata.name = req.body.name;", ["data"], []],
    ["chained assignment", "let a, b;\na = b = req.query.x;", ["a", "b"], []],
    ["compound assignment", "let s = 'a';\ns += req.query.x;", ["s"], []],
    ["for-of over tainted", "for (const item of req.body.items) { use(item); }", ["item"], []],
    ["for-of destructure Object.entries", "for (const [k, v] of Object.entries(req.query)) {}", ["k", "v"], []],
    ["map callback parameter", "const ids = req.body.ids;\nids.map((id) => lookup(id));", ["ids", "id"], []],
    ["multi declarator", "const a = 1, b = req.query.b, c = 2;", ["b"], ["a", "c"]],
    ["typed declaration", "const a: string = req.query.a as string;", ["a"], []],
    ["destructuring assignment", "let a, b;\n({ a, b } = req.body);", ["a", "b"], []],
    ["await on tainted promise var", "const p = req.json();\nconst body = await p;", ["p", "body"], []],
  ];
  it.each(cases)("%s", (_n, body, tainted, clean) => {
    const t = analyze(wrap(body));
    const names = t.taintedNames();
    for (const n of tainted) expect(names.has(n), `${n} should be tainted`).toBe(true);
    for (const n of clean) expect(names.has(n), `${n} should be clean`).toBe(false);
  });

  it("does not taint through calls to unknown functions or db clients", () => {
    const t = analyze(wrap("const id = req.params.id;\nconst user = await db.query(`select ${id}`);\nconst r = lookup(id);\nconst c = await supabase.from('t').select().eq('id', id);"));
    expect(t.isTainted("id")).toBe(true);
    expect(t.isTainted("user")).toBe(false);
    expect(t.isTainted("r")).toBe(false);
    expect(t.isTainted("c")).toBe(false);
  });

  it("is ordered: a name is tainted only after its declaration", () => {
    const raw = wrap("const before = a;\nconst a = req.query.a;\nconst after = a;");
    const t = analyze(raw);
    const at = (needle: string) => raw.indexOf(needle);
    expect(t.isTainted("a", at("const before"))).toBe(false);
    expect(t.isTainted("a", at("const after"))).toBe(true);
    expect(t.taintedNames(at("const before")).has("a")).toBe(false);
    expect(t.taintedNames().has("before")).toBe(false);
    expect(t.taintedNames().has("after")).toBe(true);
  });

  it("clears taint on sanitizing reassignment at the same level but not inside a conditional block", () => {
    const t = analyze(wrap("let q = req.query.q;\nif (!q) { q = 'default'; }\nlet n = req.query.n;\nn = Number(n);"));
    expect(t.isTainted("q")).toBe(true);
    expect(t.isTainted("n")).toBe(false);
  });

  it("scopes block-level declarations", () => {
    const raw = wrap("const id = req.query.id;\n{\n  const id = 'safe';\n  inner(id);\n}\nouter(id);");
    const t = analyze(raw);
    expect(t.isTainted("id", raw.indexOf("inner"))).toBe(false);
    expect(t.isTainted("id", raw.indexOf("outer"))).toBe(true);
  });

  it("scopes callback parameters to the callback", () => {
    const raw = wrap("const ids = req.body.ids;\nids.forEach((x) => run(x));\nconst x = 1;\nafter(x);");
    const t = analyze(raw);
    expect(t.isTainted("x", raw.indexOf("run("))).toBe(true);
    expect(t.isTainted("x", raw.indexOf("after("))).toBe(false);
  });

  it("does not mistake object keys, properties or strings for tainted names", () => {
    const t = analyze(wrap("const id = req.query.id;"));
    expect(t.isTainted("{ id: 1 }")).toBe(false);
    expect(t.isTainted("{ a: 1, id: 2 }")).toBe(false);
    expect(t.isTainted("obj.id")).toBe(false);
    expect(t.isTainted("obj?.id")).toBe(false);
    expect(t.isTainted("'id'")).toBe(false);
    expect(t.isTainted("`id`")).toBe(false);
    expect(t.isTainted("{ id }")).toBe(true);
    expect(t.isTainted("`x ${id}`")).toBe(true);
    expect(t.isTainted("a ? id : 1")).toBe(true);
  });

  it("tracks origin", () => {
    const t = analyze(wrap("const { id } = req.params;\nconst k = id.trim();\nconst z = 1;"));
    expect(t.originOf("id")).toContain("req.params");
    expect(t.originOf("k")).toContain("req.params");
    expect(t.originOf("z")).toBeUndefined();
    expect(t.originOf("nope")).toBeUndefined();
  });
});

describe("analyzeTaint: sanitizers", () => {
  const sanitized = [
    "Number(req.query.id)",
    "parseInt(req.query.id, 10)",
    "parseFloat(req.query.n)",
    "encodeURIComponent(req.query.q)",
    "path.basename(req.query.file)",
    "schema.parse(req.body)",
    "userSchema.parse(await req.json())",
    "z.object({ id: z.string() }).parse(req.body)",
    "z.string().uuid().parse(req.params.id)",
    "Schema.safeParse(req.body).data",
  ];
  it.each(sanitized)("%s clears taint", (expr) => {
    const t = analyze(wrap(`const v = ${expr};`));
    expect(t.isTainted("v")).toBe(false);
    expect(t.isTainted(expr)).toBe(false);
  });

  it("only sanitizes the wrapped value, not the rest of the expression", () => {
    const t = analyze(wrap("const v = Number(req.query.a) + req.query.b;\nconst w = `${Number(req.query.a)}`;"));
    expect(t.isTainted("v")).toBe(true);
    expect(t.isTainted("w")).toBe(false);
  });

  it("JSON.parse is not a sanitizer", () => {
    expect(analyze(wrap("const v = JSON.parse(req.body.raw);")).isTainted("v")).toBe(true);
  });

  it("supports caller-supplied sanitizers, additive by default and replace-all optionally", () => {
    const body = "const a = req.query.a;\nconst c = String(a);\nconst d = path.join('/x', a);";
    const base = analyze(wrap(body));
    expect(base.isTainted("c")).toBe(true);
    const extra = analyze(wrap(body), "h", "a.ts", { extraSanitizers: [/^String\($/] });
    expect(extra.isTainted("c")).toBe(false);
    expect(extra.isTainted("d")).toBe(true);
    const replaced = analyze(wrap(body), "h", "a.ts", { sanitizers: [/^path\.join\($/] });
    expect(replaced.isTainted("d")).toBe(false);
    expect(replaced.isTainted("c")).toBe(true);
  });
});

describe("analyzeTaint: seeds by unit role", () => {
  it("Next route handlers: request and destructured params are tainted; ctx.params works", () => {
    const s = src(NEXT_ROUTE_PATH, NEXT_ROUTE);
    const hs = handlerUnits(s);
    const get = analyzeTaint(s, hs.find((h) => h.httpMethod === "GET")!);
    expect(get.isTainted("id")).toBe(true);
    expect(get.isTainted("(await params).id")).toBe(true);
    expect(get.isTainted("user")).toBe(false);
    expect(get.isTainted("supabase")).toBe(false);
    const del = analyzeTaint(s, hs.find((h) => h.httpMethod === "DELETE")!);
    expect(del.isTainted("id")).toBe(true);
    expect(del.isTainted("force")).toBe(true);
    expect(del.isTainted("url")).toBe(true);
    const post = analyzeTaint(s, hs.find((h) => h.httpMethod === "POST")!);
    expect(post.isTainted("raw")).toBe(true);
    expect(post.isTainted("label")).toBe(true);
    expect(post.isTainted("n")).toBe(false);
    expect(post.isTainted("body")).toBe(false);
    expect(post.isTainted("name")).toBe(false);
  });

  it("Express: three routes, taint must not leak between them", () => {
    const s = src(EXPRESS_PATH, EXPRESS_APP);
    const [r1, r2, r3] = handlerUnits(s).map((u) => analyzeTaint(s, u));
    expect(r1!.isTainted("id")).toBe(true);
    expect(r1!.isTainted("user")).toBe(false);
    expect(r2!.isTainted("title")).toBe(true);
    expect(r2!.isTainted("id")).toBe(false);
    expect(r2!.taintedNames().has("id")).toBe(false);
    expect(r2!.taintedNames().has("user")).toBe(false);
    expect(r3!.isTainted("safe")).toBe(false);
    expect(r3!.isTainted("title")).toBe(false);
    expect(r3!.isTainted("filename")).toBe(false);
    expect(r3!.taintedNames().has("req")).toBe(true);
    expect(r3!.taintedNames().has("res")).toBe(false);
  });

  it("server actions: every parameter is tainted", () => {
    const s = src(ACTIONS_PATH, ACTIONS);
    const units = findUnits(s);
    const upd = analyzeTaint(s, units.find((u) => u.name === "updateProfile")!);
    expect(upd.isTainted("formData")).toBe(true);
    expect(upd.isTainted("name")).toBe(true);
    expect(upd.isTainted("bio")).toBe(true);
    expect(upd.isTainted("session")).toBe(false);
    const del = analyzeTaint(s, units.find((u) => u.name === "deleteAccount")!);
    expect(del.isTainted("userId")).toBe(true);
    expect(del.originOf("userId")).toMatch(/action/i);
    const helper = analyzeTaint(s, units.find((u) => u.name === "internalHelper")!);
    expect(helper.isTainted("x")).toBe(false);
  });

  it("inline server actions", () => {
    const s = src(INLINE_ACTION_PATH, INLINE_ACTION);
    const save = analyzeTaint(s, findUnits(s).find((u) => u.name === "save")!);
    expect(save.isTainted("formData")).toBe(true);
  });

  it("Hono and Koa handlers rely on request patterns, not on tainting c / ctx", () => {
    const hono = src("a.ts", "import { Hono } from 'hono';\nconst app = new Hono();\napp.post('/x', async (c) => {\n  const body = await c.req.json();\n  const u = c.get('user');\n  return c.json(body);\n});\n");
    const t = analyzeTaint(hono, handlerUnits(hono)[0]!);
    expect(t.isTainted("body")).toBe(true);
    expect(t.isTainted("u")).toBe(false);
    expect(t.isTainted("c")).toBe(false);
    const koa = src("a.js", "const router = new Router();\nrouter.get('/k', async (ctx) => {\n  const q = ctx.query.q;\n  const me = ctx.state.user;\n});\n");
    const k = analyzeTaint(koa, handlerUnits(koa)[0]!);
    expect(k.isTainted("q")).toBe(true);
    expect(k.isTainted("me")).toBe(false);
  });

  it("SvelteKit-style destructured first parameter", () => {
    const s = src("src/routes/api/+server.ts", "export const GET = async ({ url, params, locals }) => {\n  const q = url.searchParams.get('q');\n  const me = locals.user;\n};\n");
    const unit = findUnits(s).find((u) => u.name === "GET")!;
    const t = analyzeTaint(s, unit);
    expect(t.isTainted("q")).toBe(true);
    expect(t.isTainted("me")).toBe(false);
  });

  it("plain functions are not seeded but still see request patterns", () => {
    const t = analyze("function h(x) { const a = req.body.a; const b = x; }", "h", "lib.ts");
    expect(t.isTainted("a")).toBe(true);
    expect(t.isTainted("b")).toBe(false);
  });

  it("seedParams:false disables parameter seeding", () => {
    const s = src(ACTIONS_PATH, ACTIONS);
    const t = analyzeTaint(s, findUnits(s).find((u) => u.name === "deleteAccount")!, { seedParams: false });
    expect(t.isTainted("userId")).toBe(false);
  });

  it("top-level module consts are visible to every unit; other units' locals are not", () => {
    const s = src(
      "lib.ts",
      "const FIXED = req.body;\nfunction a(req) { const secret = req.body.s; }\nfunction b() { return FIXED + secret; }\n",
    );
    const units = findUnits(s);
    const b = analyzeTaint(s, units.find((u) => u.name === "b")!);
    expect(b.isTainted("FIXED")).toBe(true);
    expect(b.isTainted("secret")).toBe(false);
  });

  it("handles expression-bodied arrows and empty bodies", () => {
    const s = src("lib.ts", "const f = (x) => x.y;\nconst g = () => {};\n");
    for (const u of findUnits(s)) expect(() => analyzeTaint(s, u).taintedNames()).not.toThrow();
  });
});

describe("analyzeTaint: robustness", () => {
  it("terminates on pathological and malformed input", () => {
    const raw = wrap("let a = a = a = a;\nconst { = } = ;\nfor (const of ) {}\nconst {{{ = req.body;\nx = = y;");
    const s = src("a.ts", raw);
    const unit = { name: "h", kind: "function" as const, exported: false, start: 0, end: raw.length, bodyStart: raw.indexOf("{"), params: "req" };
    expect(() => analyzeTaint(s, unit).taintedNames()).not.toThrow();
  });

  it("handles a large unit quickly", () => {
    const lines = Array.from({ length: 3000 }, (_, i) => `const v${i} = ${i === 0 ? "req.query.a" : `v${i - 1} + 1`};`).join("\n");
    const t0 = Date.now();
    const t = analyze(wrap(lines));
    expect(t.isTainted("v2999")).toBe(true);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

// Public-repo study regression: stripping everything outside a safe character class sanitizes.
describe("allow-list stripping sanitizes", () => {
  const unitFor = (body: string) => {
    const src = createSource("app/api/x/route.ts", `export async function POST(req: Request) {\n  const { phone } = await req.json();\n${body}\n}\n`);
    return { src, unit: handlerUnits(src)[0]! };
  };
  it("treats .replace(/\\D/g, '') and /[^a-z0-9_-]/gi stripping as clean, through chains", () => {
    const { src, unit } = unitFor('  const digits = phone.replace(/^\\+/, "").replace(/\\D/g, "");\n  const slug = phone.replace(/[^a-z0-9_-]/gi, "");\n  sink(digits, slug);');
    const t = analyzeTaint(src, unit);
    expect(t.isTainted("digits")).toBe(false);
    expect(t.isTainted("slug")).toBe(false);
  });
  it("control: replacements that keep risky characters or insert text stay tainted", () => {
    const { src, unit } = unitFor('  const a = phone.replace(/[^a-z0-9.,()]/g, "");\n  const b = phone.replace(/\\D/g, "x");\n  const c = phone.replace(/ /g, "");\n  sink(a, b, c);');
    const t = analyzeTaint(src, unit);
    expect([t.isTainted("a"), t.isTainted("b"), t.isTainted("c")]).toEqual([true, true, true]);
  });
});
