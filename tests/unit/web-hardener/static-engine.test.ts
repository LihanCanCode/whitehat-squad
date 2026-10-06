import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/web-hardener/index.js";
import { memContext } from "../../helpers/memfs.js";

async function scan(files: Record<string, string>, frameworks: ("next" | "vite")[] = []) {
  return agent.run(memContext(files, { stack: { frameworks, backends: [], routes: [] } }));
}
const ids = (fs: { ruleId: string }[]): string[] => fs.map((f) => f.ruleId);
const of = <T extends { ruleId: string }>(fs: T[], id: string): T[] => fs.filter((f) => f.ruleId === id);

describe("comments, strings, ignored and test files", () => {
  it("does not report a commented-out source map flag", async () => {
    const f = await scan({ "next.config.js": "module.exports = {\n  // productionBrowserSourceMaps: true,\n  /* productionBrowserSourceMaps: true */\n  async headers() { return []; },\n};\n" }, ["next"]);
    expect(ids(f)).not.toContain("WEB-001");
  });
  it("control: the live flag is still reported", async () => {
    const f = await scan({ "next.config.js": "module.exports = {\n  productionBrowserSourceMaps: true,\n  async headers() { return []; },\n};\n" }, ["next"]);
    expect(of(f, "WEB-001")[0]?.evidence[0]?.line).toBe(2);
  });
  it("does not report commented-out permissive CORS", async () => {
    const src = "/* app.use(cors({ origin: true, credentials: true })) */\n// app.use(cors({ origin: true, credentials: true }))\nconst s = 'cors({ origin: true, credentials: true })';\n";
    expect(ids(await scan({ "server.ts": src }))).not.toContain("WEB-002");
  });
  // .gitignore cannot hide committed code (security review); test paths are still skipped.
  it("skips test paths but not gitignored source", async () => {
    const bad = "el.innerHTML = userInput;\n";
    const f = await scan({ ".gitignore": "gen/\n", "gen/a.js": bad, "tests/b.js": bad, "src/c.js": bad });
    expect(of(f, "WEB-003").map((x) => x.evidence[0]?.file).sort()).toEqual(["gen/a.js", "src/c.js"]);
  });
  it("ignores sinks that only appear in comments and strings", async () => {
    const src = "// el.innerHTML = userInput;\nconst doc = 'el.innerHTML = userInput';\n";
    expect(ids(await scan({ "a.js": src }))).not.toContain("WEB-003");
  });
});

describe("WEB-006 taint precision", () => {
  const upload = (body: string, head = ""): Record<string, string> => ({
    "app/api/upload/route.ts": `${head}export async function POST(request) {\n  const formData = await request.formData();\n${body}\n}\n`,
  });
  const FS = 'import fs from "node:fs/promises";\n';
  it("does not treat user.name or err.name as attacker-controlled", async () => {
    const f = await scan(upload("  const user = await getUser();\n  const out = `${user.name}.txt`;\n  await fs.writeFile(path.join(dir, out), data);", FS));
    expect(ids(f)).not.toContain("WEB-006");
    const g = await scan(upload("  try { x(); } catch (err) { await fs.writeFile(path.join(dir, err.name), data); }", FS));
    expect(ids(g)).not.toContain("WEB-006");
  });
  it("control: an uploaded file's name still reaches fs.writeFile", async () => {
    const f = await scan(upload("  const file = formData.get('f');\n  await fs.writeFile(path.join(dir, file.name), buf);", FS));
    expect(ids(f)).toContain("WEB-006");
  });
  it("uses the nearest declaration, not the first one in the file", async () => {
    const src = [
      'import fs from "fs";',
      "export async function GET(req) {",
      "  const name = req.query.name;",
      "  return Response.json({ name });",
      "}",
      "export async function POST(req) {",
      "  const name = 'report.pdf';",
      "  fs.writeFileSync(path.join(dir, name), data);",
      "}",
    ].join("\n");
    expect(ids(await scan({ "app/api/x/route.ts": src }))).not.toContain("WEB-006");
  });
  it("only counts fs receivers or an imported writeFile", async () => {
    const other = await scan(upload("  const file = formData.get('f');\n  await storage.writeFile(file.name, buf);\n  zip.cp(file.name, buf);"));
    expect(ids(other)).not.toContain("WEB-006");
    const foreign = await scan(upload("  const file = formData.get('f');\n  await writeFile(file.name, buf);", 'import { writeFile } from "./my-storage";\n'));
    expect(ids(foreign)).not.toContain("WEB-006");
    const real = await scan(upload("  const file = formData.get('f');\n  await writeFile(file.name, buf);", 'import { writeFile } from "node:fs/promises";\n'));
    expect(ids(real)).toContain("WEB-006");
  });
});

describe("WEB-003 sanitizer must wrap the value", () => {
  it("flags the unsanitized sink next to a sanitized one", async () => {
    const src = "import DOMPurify from 'dompurify';\nexport const A = ({ a, b }) => (<div><p dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(a) }} /><p dangerouslySetInnerHTML={{ __html: b }} /></div>);\n";
    expect(of(await scan({ "a.tsx": src }), "WEB-003")).toHaveLength(1);
  });
  it("accepts a variable assigned from a sanitizer", async () => {
    const src = "import DOMPurify from 'dompurify';\nexport const A = ({ a }) => { const clean = DOMPurify.sanitize(a); return <p dangerouslySetInnerHTML={{ __html: clean }} />; };\n";
    expect(ids(await scan({ "a.tsx": src }))).not.toContain("WEB-003");
  });
  it("rejects a variable that is sanitized and then appended to", async () => {
    const src = "import DOMPurify from 'dompurify';\nexport const A = ({ a, b }) => { let h = DOMPurify.sanitize(a); h += b; return <p dangerouslySetInnerHTML={{ __html: h }} />; };\n";
    expect(ids(await scan({ "a.tsx": src }))).toContain("WEB-003");
  });
  it("flags JSON.stringify of user data inside an inline script (</script> breakout)", async () => {
    const src = 'export default function P({ searchParams }) {\n  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify({ q: searchParams.q }) }} />;\n}\n';
    const hit = of(await scan({ "app/p.tsx": src }), "WEB-003");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.explanation).toContain("</script>");
  });
  it("accepts escaped or constant JSON-LD", async () => {
    const esc = "export default function P({ searchParams }) {\n  return <script dangerouslySetInnerHTML={{ __html: JSON.stringify({ q: searchParams.q }).replace(/</g, '\\\\u003c') }} />;\n}\n";
    const constant = "const ld = { '@context': 'https://schema.org', name: 'Acme' };\nexport const P = () => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;\n";
    expect(ids(await scan({ "app/a.tsx": esc }))).not.toContain("WEB-003");
    expect(ids(await scan({ "app/b.tsx": constant }))).not.toContain("WEB-003");
  });
  it("flags v-html with single quotes and accepts a sanitized one", async () => {
    expect(ids(await scan({ "a.vue": "<template><div v-html='post.body'></div></template>" }))).toContain("WEB-003");
    expect(ids(await scan({ "b.vue": '<template><div v-html="sanitize(post.body)"></div></template>' }))).not.toContain("WEB-003");
  });
  it("finds innerHTML inside a <script> of an html file with the right line and snippet", async () => {
    const f = of(await scan({ "public/index.html": "<html>\n<body>\n<script>\n  box.innerHTML = location.hash;\n</script>\n</body></html>" }), "WEB-003");
    expect(f[0]?.evidence[0]).toMatchObject({ line: 4, snippet: "box.innerHTML = location.hash;" });
  });
  it("accepts escaped template interpolations", async () => {
    const src = "function row(x) { el.innerHTML = `<td>${escapeHtml(x.name)}</td><td>${x.items.length}</td>`; }\n";
    expect(ids(await scan({ "a.js": src }))).not.toContain("WEB-003");
    expect(ids(await scan({ "b.js": "function row(x) { el.innerHTML = `<td>${x.name}</td>`; }\n" }))).toContain("WEB-003");
  });
});

describe("WEB-002 forms", () => {
  it("flags the Next headers() form with credentials", async () => {
    const src = "module.exports = { async headers() { return [{ source: '/api/:p*', headers: [\n { key: 'Access-Control-Allow-Origin', value: req.headers.origin },\n { key: 'Access-Control-Allow-Credentials', value: 'true' } ] }]; } };\n";
    expect(ids(await scan({ "next.config.js": src }))).toContain("WEB-002");
  });
  it("flags a reflected origin held in a variable, high severity", async () => {
    const src = "export async function GET(request) {\n  const origin = request.headers.get('origin');\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' } });\n}\n";
    const hit = of(await scan({ "app/api/x/route.ts": src }), "WEB-002");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("high");
  });
  it("control: the reflected origin is fine behind an allowlist", async () => {
    const src = "const ALLOWED = ['https://a.com'];\nexport async function GET(request) {\n  const origin = request.headers.get('origin');\n  if (!ALLOWED.includes(origin)) return new Response('no', { status: 403 });\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' } });\n}\n";
    expect(ids(await scan({ "app/api/x/route.ts": src }))).not.toContain("WEB-002");
  });
  it("cors origin '*' with credentials is low, origin true is high", async () => {
    expect(of(await scan({ "a.ts": "cors({ origin: '*', credentials: true })" }), "WEB-002")[0]?.severity).toBe("low");
    expect(of(await scan({ "b.ts": "cors({ origin: true, credentials: true })" }), "WEB-002")[0]?.severity).toBe("high");
  });
});

describe("WEB-004 header sources and evidence", () => {
  const next = { "next.config.js": "module.exports = {\n  reactStrictMode: true,\n};\n" };
  it("accepts vercel.json, netlify.toml, _headers and proxy.ts", async () => {
    const vercel = { ...next, "vercel.json": JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] }] }) };
    const netlify = { ...next, "netlify.toml": '[[headers]]\n  for = "/*"\n  [headers.values]\n    Content-Security-Policy = "default-src self"\n' };
    const underscore = { ...next, "public/_headers": "/*\n  X-Frame-Options: DENY\n" };
    const proxy = { ...next, "proxy.ts": "export function proxy(r) { const res = NextResponse.next(); res.headers.set('Content-Security-Policy', c); return res; }" };
    for (const files of [vercel, netlify, underscore, proxy]) expect(ids(await scan(files, ["next"]))).not.toContain("WEB-004");
  });
  it("control: still flagged with none of those, pointing at the real config line", async () => {
    const f = of(await scan(next, ["next"]), "WEB-004");
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence[0]).toMatchObject({ file: "next.config.js", line: 1 });
  });
  it("points at package.json when there is no next.config, never a missing file", async () => {
    const f = of(await scan({ "package.json": '{\n  "dependencies": {\n    "next": "15"\n  }\n}' }, ["next"]), "WEB-004");
    expect(f[0]?.evidence[0]).toMatchObject({ file: "package.json", line: 3 });
  });
  it("finds a nested app's package.json when the root one has no next (found by self-scan)", async () => {
    const files = {
      "package.json": '{ "name": "tools" }',
      "apps/web/package.json": '{\n  "dependencies": {\n    "next": "15"\n  }\n}',
      "node_modules/x/package.json": '{ "dependencies": { "next": "1" } }',
    };
    const f = of(await scan(files, ["next"]), "WEB-004");
    expect(f.map((x) => x.evidence[0])).toEqual([expect.objectContaining({ file: "apps/web/package.json", line: 3 })]);
  });
  it("reports each Next app of a monorepo with its own config path", async () => {
    const f = of(
      await scan({ "apps/a/next.config.js": "module.exports = {}", "apps/b/next.config.js": "module.exports = {}", "apps/b/proxy.ts": "x.headers.set('Strict-Transport-Security', 'a')" }, ["next"]),
      "WEB-004",
    );
    expect(f.map((x) => x.evidence[0]?.file)).toEqual(["apps/a/next.config.js"]);
  });
});

describe("WEB-007 / WEB-008 next image config", () => {
  const cfg = (images: string): Record<string, string> => ({ "next.config.js": `module.exports = {\n  async headers() { return []; },\n  images: {\n${images}\n  },\n};\n` });
  it("flags wildcard hostnames and domains: ['*'] as medium", async () => {
    const a = of(await scan(cfg("    remotePatterns: [{ protocol: 'https', hostname: '**' }],")), "WEB-007");
    const b = of(await scan(cfg("    remotePatterns: [{ hostname: '*' }],")), "WEB-007");
    const c = of(await scan(cfg("    domains: ['*'],")), "WEB-007");
    expect([a.length, b.length, c.length]).toEqual([1, 1, 1]);
    expect(a[0]?.severity).toBe("medium");
    expect(a[0]?.evidence[0]?.line).toBe(4);
  });
  it("is quiet for specific hosts and subdomain wildcards", async () => {
    expect(ids(await scan(cfg("    remotePatterns: [{ hostname: 'cdn.example.com' }, { hostname: '**.example.com' }],")))).not.toContain("WEB-007");
  });
  it("flags dangerouslyAllowSVG without sandbox + attachment, quiet with both", async () => {
    expect(ids(await scan(cfg("    dangerouslyAllowSVG: true,")))).toContain("WEB-008");
    const weak = of(await scan(cfg("    dangerouslyAllowSVG: true,\n    contentSecurityPolicy: \"default-src 'self'\",")), "WEB-008");
    expect(weak[0]?.confidence).toBe("high");
    const ok = cfg("    dangerouslyAllowSVG: true,\n    contentDispositionType: 'attachment',\n    contentSecurityPolicy: \"default-src 'self'; script-src 'none'; sandbox;\",");
    expect(ids(await scan(ok))).not.toContain("WEB-008");
  });
  it("ignores a commented-out wildcard", async () => {
    expect(ids(await scan(cfg("    // remotePatterns: [{ hostname: '**' }],")))).not.toContain("WEB-007");
  });
});

describe("WEB-009 / WEB-010 postMessage", () => {
  it("flags a message listener that uses event.data with no origin check", async () => {
    const src = "window.addEventListener('message', (event) => {\n  setUser(event.data.user);\n});\n";
    const hit = of(await scan({ "src/a.js": src }), "WEB-009");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("medium");
  });
  it("is quiet when origin is compared, an allowlist is used, or data is unused", async () => {
    expect(ids(await scan({ "a.js": "window.addEventListener('message', (e) => {\n  if (e.origin !== 'https://app.example.com') return;\n  use(e.data);\n});" }))).not.toContain("WEB-009");
    expect(ids(await scan({ "b.js": "const ALLOWED = ['x'];\nwindow.addEventListener('message', (e) => {\n  if (!ALLOWED.includes(e.origin)) return;\n  use(e.data);\n});" }))).not.toContain("WEB-009");
    expect(ids(await scan({ "c.js": "window.addEventListener('message', (e) => { console.log('hi'); });" }))).not.toContain("WEB-009");
  });
  it("resolves a handler passed by name and ignores a commented listener", async () => {
    const named = "const onMsg = (e) => { run(e.data); };\nwindow.addEventListener('message', onMsg);\n";
    expect(ids(await scan({ "a.js": named }))).toContain("WEB-009");
    expect(ids(await scan({ "b.js": "// window.addEventListener('message', (e) => run(e.data));\n" }))).not.toContain("WEB-009");
  });
  it("flags postMessage(token, '*') as high, quiet for a specific origin or harmless data", async () => {
    const hit = of(await scan({ "a.js": "opener.postMessage({ type: 'done', token }, '*');" }), "WEB-010");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("high");
    expect(ids(await scan({ "b.js": "opener.postMessage({ type: 'done', token }, 'https://app.example.com');" }))).not.toContain("WEB-010");
    expect(ids(await scan({ "c.js": "parent.postMessage({ height: 40 }, '*');" }))).not.toContain("WEB-010");
  });
  it("sees a sensitive payload held in a variable", async () => {
    expect(ids(await scan({ "a.js": "const payload = { sessionId: s };\nwin.postMessage(payload, '*');" }))).toContain("WEB-010");
  });
});

describe("WEB-011 error details returned to clients", () => {
  const route = (catchBody: string): Record<string, string> => ({
    "app/api/x/route.ts": `export async function POST(req: Request) {\n  try {\n    await work();\n  } catch (e) {\n${catchBody}\n  }\n}\n`,
  });
  it("flags e.message as medium and e.stack as high", async () => {
    const m = of(await scan(route("    return Response.json({ error: e.message }, { status: 500 });")), "WEB-011");
    expect(m).toHaveLength(1);
    expect(m[0]?.severity).toBe("medium");
    const s = of(await scan(route("    return Response.json({ error: e.stack }, { status: 500 });")), "WEB-011");
    expect(s[0]?.severity).toBe("high");
  });
  it("flags NextResponse.json(err), String(e), res.send(err) and express res.status(500).json", async () => {
    expect(ids(await scan(route("    return NextResponse.json(e, { status: 500 });")))).toContain("WEB-011");
    expect(ids(await scan(route("    return Response.json({ error: String(e) });")))).toContain("WEB-011");
    const ex = "app.post('/x', async (req, res) => {\n  try { await w(); } catch (err) {\n    res.status(500).json({ error: err.message });\n  }\n});\n";
    expect(ids(await scan({ "server.js": ex }))).toContain("WEB-011");
    expect(ids(await scan({ "s2.js": "app.post('/x', (req, res) => { try { w(); } catch (err) { res.send(err); } });" }))).toContain("WEB-011");
  });
  it("flags an Express error-handling middleware", async () => {
    expect(ids(await scan({ "server.js": "app.use((err, req, res, next) => {\n  res.status(500).json({ message: err.message });\n});\n" }))).toContain("WEB-011");
  });
  it("is quiet for generic messages, dev-only branches and safe error classes", async () => {
    expect(ids(await scan(route("    console.error(e);\n    return Response.json({ error: 'Internal error' }, { status: 500 });")))).not.toContain("WEB-011");
    expect(ids(await scan(route("    if (process.env.NODE_ENV !== 'production') return Response.json({ error: e.stack });\n    return Response.json({ error: 'Internal error' });")))).not.toContain("WEB-011");
    expect(ids(await scan(route("    if (e instanceof ZodError) return Response.json({ error: e.message }, { status: 400 });\n    return Response.json({ error: 'Internal error' });")))).not.toContain("WEB-011");
    expect(ids(await scan(route("    if (e instanceof AppError) { return Response.json({ error: e.message }, { status: e.status }); }\n    return Response.json({ error: 'x' });")))).not.toContain("WEB-011");
  });
  it("ignores catch blocks outside request handlers", async () => {
    const src = "export async function helper() {\n  try { await w(); } catch (e) { return { error: e.message }; }\n}\n";
    expect(ids(await scan({ "lib/h.ts": src }))).not.toContain("WEB-011");
  });
});

describe("corpus regressions", () => {
  it("WEB-006: follows a request file into a local save helper", async () => {
    const src = [
      "export async function POST(request) {",
      "  const formData = await request.formData();",
      "  const photo = formData.get('photo');",
      "  const saveFile = async (file) => {",
      "    const filename = `${Date.now()}_${file.name.replace(/\s/g, '_')}`;",
      "    await writeFile(path.join(uploadDir, filename), Buffer.from(await file.arrayBuffer()));",
      "  };",
      "  await saveFile(photo);",
      "}",
    ].join("\n");
    expect(ids(await scan({ "app/api/register/route.ts": src }))).toContain("WEB-006");
  });
  it("WEB-006 control: the same helper called with a constant is quiet", async () => {
    const src = "export async function POST(request) {\n  const saveFile = async (file) => { await writeFile(path.join(dir, file.name), b); };\n  await saveFile({ name: 'x.txt' });\n}\n";
    expect(ids(await scan({ "app/api/register/route.ts": src }))).not.toContain("WEB-006");
  });
  it("WEB-003: copying an element's own innerHTML into document.write is not injection", async () => {
    expect(ids(await scan({ "a.tsx": "w.document.write(ticketElement.innerHTML);\n" }))).not.toContain("WEB-003");
    expect(ids(await scan({ "b.tsx": "w.document.write(location.hash);\n" }))).toContain("WEB-003");
  });
  it("WEB-003: numeric template parts (toFixed, length) are safe, names are not", async () => {
    expect(ids(await scan({ "a.js": "el.innerHTML = `<span>${(x / 1000).toFixed(0)}k</span>`;\n" }))).not.toContain("WEB-003");
    expect(ids(await scan({ "b.js": "el.innerHTML = `<span>${file.name}</span>`;\n" }))).toContain("WEB-003");
  });
  it("WEB-011: Stripe webhook signature errors are not an internal leak", async () => {
    const hook = "export async function POST(req) {\n  try {\n    event = stripe.webhooks.constructEvent(body, sig, secret);\n  } catch (err) {\n    return new Response(`Webhook Error: ${err.message}`, { status: 400 });\n  }\n}\n";
    expect(ids(await scan({ "app/api/webhooks/route.ts": hook }))).not.toContain("WEB-011");
    const plain = "export async function POST(req) {\n  try {\n    await save(body);\n  } catch (err) {\n    return new Response(`Error: ${err.message}`, { status: 500 });\n  }\n}\n";
    expect(ids(await scan({ "app/api/save/route.ts": plain }))).toContain("WEB-011");
  });
  it("WEB-011: dev-server plugins inside vite.config are not production handlers", async () => {
    const cfg = "export default { plugins: [{ configureServer(server) { server.middlewares.use(async (req, res) => { try { go(); } catch (err) { res.statusCode = 500; res.end(JSON.stringify({ error: err.message })); } }); } }] };\n";
    expect(ids(await scan({ "vite.config.ts": cfg }))).not.toContain("WEB-011");
  });
});
