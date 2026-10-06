import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/web-hardener/index.js";
import { memContext } from "../../helpers/memfs.js";

async function scan(files: Record<string, string>, frameworks: ("next" | "vite")[] = []) {
  const ctx = memContext(files, { stack: { frameworks, backends: [], routes: [] } });
  return agent.run(ctx);
}
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId);

describe("web-hardener metadata", () => {
  it("declares id and modes", () => {
    expect(agent.id).toBe("web-hardener");
    expect(agent.modes).toEqual(["static", "live"]);
  });
  it("returns nothing in live mode without an http client", async () => {
    const ctx = memContext({}, { mode: "live" });
    expect(await agent.run(ctx)).toEqual([]);
  });
});

describe("WEB-001 source maps", () => {
  it("flags next productionBrowserSourceMaps", async () => {
    const f = await scan({ "next.config.js": "module.exports = {\n productionBrowserSourceMaps: true,\n headers() {} }" });
    const hit = f.find((x) => x.ruleId === "WEB-001");
    expect(hit?.evidence[0]).toMatchObject({ file: "next.config.js", line: 2 });
  });
  it("flags vite sourcemap true but not hidden", async () => {
    expect(ids(await scan({ "vite.config.ts": "export default { build: { sourcemap: true } }" }))).toContain("WEB-001");
    expect(ids(await scan({ "vite.config.ts": "export default { build: { sourcemap: 'hidden' } }" }))).not.toContain("WEB-001");
  });
  it("flags webpack devtool source-map", async () => {
    expect(ids(await scan({ "webpack.config.js": "module.exports = { devtool: 'source-map' }" }))).toContain("WEB-001");
    expect(ids(await scan({ "webpack.config.js": "module.exports = { devtool: false }" }))).not.toContain("WEB-001");
  });
});

describe("WEB-002 permissive CORS", () => {
  it("flags cors origin true with credentials", async () => {
    const f = await scan({ "server.ts": "app.use(cors({ origin: true, credentials: true }))" });
    expect(f.find((x) => x.ruleId === "WEB-002")?.severity).toBe("high");
  });
  it("reports wildcard header with credentials only as low (browsers refuse it)", async () => {
    const src = `res.setHeader("Access-Control-Allow-Origin", "*");\nres.setHeader("Access-Control-Allow-Credentials", "true");`;
    expect((await scan({ "a.js": src })).find((x) => x.ruleId === "WEB-002")?.severity).toBe("low");
  });
  it("flags reflected origin with credentials", async () => {
    const src = `res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\nres.setHeader("Access-Control-Allow-Credentials", "true");`;
    expect(ids(await scan({ "a.js": src }))).toContain("WEB-002");
  });
  it("ignores allow-listed origin and wildcard without credentials", async () => {
    expect(ids(await scan({ "a.ts": "cors({ origin: 'https://app.example.com', credentials: true })" }))).not.toContain("WEB-002");
    expect(ids(await scan({ "a.ts": "cors({ origin: '*' })" }))).not.toContain("WEB-002");
  });
});

describe("WEB-003 unsafe HTML sinks", () => {
  it("flags dangerouslySetInnerHTML with a variable", async () => {
    const f = await scan({ "c.tsx": "export const C = ({h}) => <div dangerouslySetInnerHTML={{ __html: h }} />" });
    const hit = f.find((x) => x.ruleId === "WEB-003");
    expect(hit?.severity).toBe("high");
    expect(hit?.confidence).toBe("medium");
  });
  it("flags innerHTML, outerHTML, document.write and v-html", async () => {
    const f = await scan({
      "a.js": "el.innerHTML = userInput;\nel.outerHTML = `<p>${x}</p>`;\ndocument.write(location.hash);",
      "b.vue": '<div v-html="post.body"></div>',
    });
    expect(f.filter((x) => x.ruleId === "WEB-003")).toHaveLength(4);
  });
  it("ignores literal values", async () => {
    const src = `el.innerHTML = "";\nel.innerHTML = '<b>hi</b>';\nel.innerHTML = \`static\`;\nel.innerHTML == x;`;
    expect(ids(await scan({ "a.js": src }))).not.toContain("WEB-003");
  });
  it("accepts a sanitizer that wraps the value reaching the sink, and a constant JSON.stringify", async () => {
    expect(ids(await scan({ "a.tsx": "import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(x);" }))).not.toContain("WEB-003");
    expect(ids(await scan({ "b.tsx": "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />" }))).not.toContain("WEB-003");
  });
  it("no longer lets a sanitizer mention elsewhere in the file hide an unsanitized sink", async () => {
    expect(ids(await scan({ "a.tsx": "import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(x);\nel.innerHTML = y;" }))).toContain("WEB-003");
  });
  it("ignores test files", async () => {
    expect(ids(await scan({ "a.test.ts": "el.innerHTML = x;" }))).not.toContain("WEB-003");
  });
});

describe("WEB-004 missing security headers in Next.js", () => {
  it("flags next config without headers() and offers a ready block", async () => {
    const f = await scan({ "next.config.js": "module.exports = {}" }, ["next"]);
    const hit = f.find((x) => x.ruleId === "WEB-004");
    expect(hit?.severity).toBe("low");
    expect(hit?.fix.config).toContain("async headers()");
    expect(hit?.fix.config).toContain("Content-Security-Policy");
  });
  it("flags when only the stack says next", async () => {
    expect(ids(await scan({}, ["next"]))).toContain("WEB-004");
  });
  it("accepts headers() in config", async () => {
    expect(ids(await scan({ "next.config.mjs": "export default { async headers() { return [] } }" }, ["next"]))).not.toContain("WEB-004");
  });
  it("accepts middleware that sets CSP or HSTS", async () => {
    const mw = "res.headers.set('Content-Security-Policy', csp)";
    expect(ids(await scan({ "next.config.js": "module.exports={}", "src/middleware.ts": mw }, ["next"]))).not.toContain("WEB-004");
  });
  it("does not run for non-next projects", async () => {
    expect(ids(await scan({ "vite.config.ts": "export default {}" }, ["vite"]))).not.toContain("WEB-004");
  });
});

describe("target=_blank is no longer reported", () => {
  it("modern browsers imply noopener, so the old WEB-005 rule was removed as noise", async () => {
    expect(ids(await scan({ "l.tsx": '<a href={user.site} target="_blank">x</a>' }))).not.toContain("WEB-005");
  });
});

describe("static misc", () => {
  it("is quiet on clean files and skips unreadable ones", async () => {
    const ctx = memContext({ "a.ts": "export const x = 1;" });
    const orig = ctx.files.read;
    const ctx2 = { ...ctx, files: { ...ctx.files, paths: [...ctx.files.paths, "ghost.ts"], read: orig } };
    expect(await agent.run(ctx2)).toEqual([]);
  });
});
