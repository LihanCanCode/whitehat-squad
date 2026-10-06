import { describe, expect, it } from "vitest";
import { agent as injection } from "../../src/agents/injection-hunter/index.js";
import { agent as web } from "../../src/agents/web-hardener/index.js";
import { memContext } from "../helpers/memfs.js";

// False-positive classes found by hand-checking a public-repo study sample, each with a control.

const run = async (a: typeof web, files: Record<string, string>, id: string) =>
  (await a.run(memContext(files))).filter((f) => f.ruleId === id);

describe("INJ-003 inside an anonymous Deno.serve handler", () => {
  const fn = (decl: string) => `Deno.serve(async (req) => {
  const body = await req.json();
  const rawPhone = body.phone;
  ${decl}
  const international = digits;
  const { data } = await supabase.from("customers").select("id").or(\`phone.eq.\${international}\`);
  return new Response("ok");
});
`;
  it("digits-only values (.replace(/\\D/g, '')) are safe in a PostgREST filter", async () => {
    const decl = 'let digits = rawPhone.replace(/^\\+/, "").replace(/\\D/g, "");\n  if (digits.startsWith("0")) digits = "353" + digits.slice(1);';
    expect(await run(injection, { "supabase/functions/x/index.ts": fn(decl) }, "INJ-003")).toEqual([]);
  });
  it("control: the raw value still fires", async () => {
    expect(await run(injection, { "supabase/functions/x/index.ts": fn("const digits = rawPhone;") }, "INJ-003")).toHaveLength(1);
  });
});

describe("INJ-006: the page's own pathname", () => {
  const page = (url: string) =>
    `"use client";\nimport { usePathname, useRouter, useSearchParams } from "next/navigation";\nexport function P() {\n  const router = useRouter();\n  const pathname = usePathname();\n  const sp = useSearchParams();\n  const next = new URLSearchParams(sp.toString());\n  const qs = next.toString();\n  const go = () => router.push(${url});\n  return null;\n}\n`;
  it("pathname + query string cannot change the origin", async () => {
    expect(await run(injection, { "app/x/page.tsx": page("`${pathname}?${qs}`") }, "INJ-006")).toEqual([]);
  });
  it("control: a search-param target still fires", async () => {
    expect(await run(injection, { "app/x/page.tsx": page('sp.get("next")') }, "INJ-006")).toHaveLength(1);
  });
});

describe("WEB-003 calibration", () => {
  it("an imported UPPER_SNAKE_CASE constant is safe", async () => {
    const src = 'import { THEME_INIT_SCRIPT } from "./theme";\nexport const H = () => <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />;\n';
    expect(await run(web, { "app/root.tsx": src }, "WEB-003")).toEqual([]);
  });
  it("an untraced value is reported at low confidence; a prop or URL value stays medium", async () => {
    const untraced = "export function show(n) {\n  const p = pages[n];\n  box.innerHTML = p.html;\n}\n";
    expect((await run(web, { "a.js": untraced }, "WEB-003"))[0]?.confidence).toBe("low");
    const prop = "export const C = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;\n";
    expect((await run(web, { "c.tsx": prop }, "WEB-003"))[0]?.confidence).toBe("medium");
    const url = "el.innerHTML = location.hash;\n";
    expect((await run(web, { "b.js": url }, "WEB-003"))[0]?.confidence).toBe("medium");
  });
  it("skips minified bundles, but still scans normal files", async () => {
    const bundle = `${"var a=function(){return 1};".repeat(400)}el.innerHTML=location.hash;`;
    expect(await run(web, { "public/app.html": `<script>${bundle}</script>` }, "WEB-003")).toEqual([]);
    expect(await run(web, { "public/app.js": "el.innerHTML = location.hash;\n" }, "WEB-003")).toHaveLength(1);
  });
});
