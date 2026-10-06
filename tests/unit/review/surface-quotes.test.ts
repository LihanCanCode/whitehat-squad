import { describe, expect, it } from "vitest";
import { buildUnits, localImports, redactSecrets } from "../../../src/review/surface.js";
import { allQuotesReal, quoteIsReal, shownLines } from "../../../src/review/quotes.js";
import { memFiles } from "../../helpers/memfs.js";
import { APP } from "./fixtures.js";

describe("buildUnits", () => {
  it("makes one unit per handler and Server Action, skipping client components", async () => {
    const units = await buildUnits(memFiles(APP), []);
    expect(units.map((u) => u.id).sort()).toEqual(["app/actions/orders.ts#placeOrder", "app/api/notes/[id]/route.ts#GET /api/notes/[id]"]);
  });

  it("includes one hop of local imports (the helper where the IDOR lives), line-numbered", async () => {
    const units = await buildUnits(memFiles(APP), []);
    const notes = units.find((u) => u.file === "app/api/notes/[id]/route.ts");
    expect(notes?.related.map((r) => r.file)).toEqual(["lib/supabase.ts", "lib/notes.ts"]);
    expect(notes?.related[1]?.excerpt).toContain('4 |   const { data } = await supabase.from("notes")');
    expect(notes?.guards).toContain("auth");
  });

  it("never sends .env files and redacts secret-shaped tokens and known secrets", async () => {
    const leak = { ...APP, "lib/pay.ts": 'export const key = "sk_live_51' + "Zz9".repeat(30) + '";\nexport const internal = "my-known-secret-value";\n', "app/api/pay/route.ts": 'import { key } from "@/lib/pay";\nexport async function POST() { return Response.json({ key }); }\n' };
    const units = await buildUnits(memFiles(leak), [], new Set(["my-known-secret-value"]));
    const text = JSON.stringify(units);
    expect(text).not.toContain("sk_live_51Zz9");
    expect(text).not.toContain("my-known-secret-value");
    expect(text).not.toContain("STRIPE_SECRET_KEY");
    expect(text).toContain("[REDACTED]");
  });

  it("adds one unit for SQL policies and orders units by risk", async () => {
    const files = { ...APP, "supabase/migrations/1.sql": "create policy p on public.notes for select using (true);\n" };
    const units = await buildUnits(memFiles(files), []);
    expect(units.some((u) => u.kind === "sql" && u.excerpt.includes("1 | create policy"))).toBe(true);
    expect(units.map((u) => u.score)).toEqual([...units.map((u) => u.score)].sort((a, b) => b - a));
  });

  it("gives each unit a content hash that changes when its code changes", async () => {
    const a = await buildUnits(memFiles(APP), []);
    const b = await buildUnits(memFiles({ ...APP, "lib/notes.ts": APP["lib/notes.ts"]!.replace(".single()", ".maybeSingle()") }), []);
    const hash = (us: typeof a, f: string) => us.find((u) => u.file === f)?.contentHash;
    expect(hash(a, "app/actions/orders.ts")).toBe(hash(b, "app/actions/orders.ts"));
    expect(hash(a, "app/api/notes/[id]/route.ts")).not.toBe(hash(b, "app/api/notes/[id]/route.ts"));
  });
});

describe("localImports", () => {
  it("resolves relative and @/ imports against the index, ignoring packages", () => {
    const known = new Set(["lib/a.ts", "src/lib/b.ts", "app/x/c/index.ts"]);
    const raw = 'import a from "@/lib/a";\nimport { b } from "@/lib/b";\nimport c from "./c";\nimport React from "react";\n';
    expect(localImports("app/x/page.ts", raw, known).map((i) => i.file)).toEqual(["lib/a.ts", "src/lib/b.ts", "app/x/c/index.ts"]);
  });
});

describe("quote check (anti-hallucination)", () => {
  it("accepts a real line within ±2 and rejects invented code, wrong files and tiny quotes", async () => {
    const [unit] = (await buildUnits(memFiles(APP), [])).filter((u) => u.file === "app/actions/orders.ts");
    const shown = shownLines(unit!);
    expect(quoteIsReal({ file: "app/actions/orders.ts", line: 8, quote: 'const price = Number(form.get("price"));' }, shown)).toBe(true);
    expect(quoteIsReal({ file: "app/actions/orders.ts", line: 7, quote: "const price = req.body.price;" }, shown)).toBe(false);
    expect(quoteIsReal({ file: "app/actions/orders.ts", line: 30, quote: 'const price = Number(form.get("price"));' }, shown)).toBe(false);
    expect(quoteIsReal({ file: "lib/other.ts", line: 7, quote: 'const price = Number(form.get("price"));' }, shown)).toBe(false);
    expect(quoteIsReal({ file: "app/actions/orders.ts", line: 7, quote: "c" }, shown)).toBe(false);
    expect(allQuotesReal([], shown)).toBe(false);
  });

  it("knows the lines of every file inside the SQL unit", async () => {
    const files = { "supabase/migrations/1.sql": "create policy a on t for select using (true);\n", "supabase/migrations/2.sql": "-- x\ncreate policy b on u for select using (true);\n" };
    const [sql] = await buildUnits(memFiles(files), []);
    const shown = shownLines(sql!);
    expect(quoteIsReal({ file: "supabase/migrations/2.sql", line: 2, quote: "create policy b on u for select" }, shown)).toBe(true);
  });
});

describe("redactSecrets", () => {
  it("keeps code readable while removing token values", () => {
    expect(redactSecrets('const k = "ghp_' + "a1B2".repeat(9) + '";')).toBe('const k = "[REDACTED]";');
  });
});
