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

describe("AUTH-002: project-specific require/ensure guards", () => {
  const action = (guard: string) =>
    `"use server";\nimport { supabase } from "@/lib/supabase";\nexport async function revoke(id: string) {\n  ${guard}\n  await supabase.from("links").delete().eq("id", id);\n}\n`;
  it("requireOrganizer() / requirePortalTab() count as access checks", async () => {
    const { agent } = await import("../../src/agents/auth-auditor/index.js");
    for (const g of ["const { supabase: s } = await requireOrganizer();", 'await requirePortalTab("staff");']) {
      expect((await agent.run(memContext({ "app/x/actions.ts": action(g) }))).filter((f) => f.ruleId === "AUTH-002"), g).toEqual([]);
    }
  });
  it("control: ensureDir() and no guard still fire", async () => {
    const { agent } = await import("../../src/agents/auth-auditor/index.js");
    for (const g of ['await ensureDir("/tmp/x");', ""]) {
      expect((await agent.run(memContext({ "app/x/actions.ts": action(g) }))).filter((f) => f.ruleId === "AUTH-002"), g).toHaveLength(1);
    }
  });
});

describe("DatabaseGuard calibration", () => {
  it("DB-001: with a supabase/ folder, another service's migrations are a different database", async () => {
    const { agent } = await import("../../src/agents/database-guard/index.js");
    const files = {
      "supabase/migrations/1.sql": "create table public.notes (id uuid primary key, user_id uuid);\nalter table public.notes enable row level security;\ncreate policy p on public.notes for select using (auth.uid() = user_id);\n",
      "services/billing-api/migrations/0001.sql": "CREATE TABLE purchases (token_hash TEXT PRIMARY KEY, product_id TEXT NOT NULL);\n",
    };
    const ids = (await agent.run(memContext(files))).map((f) => f.ruleId);
    expect(ids).not.toContain("DB-001");
    // control: the same table inside supabase/ still fires
    const inside = { ...files, "supabase/migrations/2.sql": "create table public.purchases (token_hash text primary key);\n" };
    expect((await agent.run(memContext(inside))).map((f) => f.ruleId)).toContain("DB-001");
  });
  it("DB-020: high only when the open function uses the service-role key", async () => {
    const { agent } = await import("../../src/agents/database-guard/index.js");
    const files = (body: string) => ({ "supabase/config.toml": "[functions.f]\nverify_jwt = false\n", "supabase/functions/f/index.ts": body });
    const sev = async (body: string) => (await agent.run(memContext(files(body)))).find((f) => f.ruleId === "DB-020")?.severity;
    expect(await sev('Deno.serve(() => new Response("<urlset/>"));\n')).toBe("medium");
    expect(await sev('const s = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nDeno.serve(async () => { await s.from("users").delete().neq("id", ""); return new Response("ok"); });\n')).toBe("high");
  });
});
