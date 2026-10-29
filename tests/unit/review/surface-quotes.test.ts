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

  it("builds FastAPI units with one hop of relative imports and no recursive expansion", async () => {
    const files = {
      "api/routes.py": 'from fastapi import APIRouter\nfrom .services import fetch_order\nrouter = APIRouter()\n\n@router.get("/orders/{order_id}")\nasync def get_order(order_id: int):\n    return fetch_order(order_id)\n',
      "api/services.py": 'from .database import query_order\ndef fetch_order(order_id):\n    return query_order(order_id)\n',
      "api/database.py": "def query_order(order_id):\n    return None\n",
    };
    const units = await buildUnits(memFiles(files), []);
    const route = units.find((u) => u.file === "api/routes.py");
    expect(route).toMatchObject({ kind: "handler", framework: "FastAPI", method: "GET", route: "/orders/{order_id}" });
    expect(route?.excerpt).toContain("async def get_order");
    expect(route?.related.map((item) => item.file)).toEqual(["api/services.py"]);
    expect(route?.related[0]?.excerpt).toContain("def fetch_order");
    expect(route?.related).not.toContainEqual(expect.objectContaining({ file: "api/database.py" }));
  });

  it("builds multiple Flask routes and deduplicates repeated routes", async () => {
    const files = {
      "app.py": 'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/items", methods=["GET", "POST"])\ndef items():\n    return []\n\n@app.get("/health")\ndef health():\n    return "ok"\n\n@app.get("/health")\ndef duplicate_health():\n    return "ok"\n',
    };
    const units = await buildUnits(memFiles(files), []);
    const routes = units.filter((u) => u.file === "app.py");
    expect(routes).toHaveLength(2);
    expect(routes.map((u) => [u.framework, u.method, u.route])).toEqual(expect.arrayContaining([
      ["Flask", "GET, POST", "/items"],
      ["Flask", "GET", "/health"],
    ]));
  });

  it("builds Django REST Framework decorated views but does not infer URLconf-only routes", async () => {
    const files = {
      "views.py": 'from django.http import JsonResponse\nfrom rest_framework.decorators import api_view\n\n@api_view(["GET", "POST"])\ndef list_items(request):\n    return JsonResponse({"items": []})\n\ndef urlconf_only(request):\n    return JsonResponse({"ok": True})\n',
      "urls.py": 'from django.urls import path\nfrom . import views\nurlpatterns = [path("items/", views.urlconf_only)]\n',
    };
    const units = await buildUnits(memFiles(files), []);
    expect(units.filter((u) => u.file === "views.py")).toMatchObject([
      { framework: "Django", method: "GET, POST", name: "GET, POST list_items" },
    ]);
    expect(units.some((u) => u.name.includes("urlconf_only"))).toBe(false);
  });

  it("ignores unresolved, duplicate, and malformed Python imports without failing", async () => {
    const files = {
      "routes.py": 'from fastapi import FastAPI\nfrom missing import thing\nfrom .helpers import lookup\nfrom .helpers import lookup as lookup_again\napp = FastAPI()\n@app.get("/x")\ndef x():\n    return lookup()\n',
      "helpers.py": "def lookup():\n    return 1\n",
      "broken.py": 'from fastapi import FastAPI\n@app.get("/broken")\ndef broken(:\n    return None\n',
    };
    const units = await buildUnits(memFiles(files), []);
    const route = units.find((u) => u.file === "routes.py");
    expect(route?.related.map((item) => item.file)).toEqual(["helpers.py"]);
    expect(units.some((u) => u.file === "broken.py")).toBe(false);
  });

  it("keeps existing JS/TS handler and SQL policy units alongside Python units", async () => {
    const files = {
      ...APP,
      "api.py": 'from fastapi import FastAPI\napp = FastAPI()\n@app.post("/x")\ndef x():\n    return {}\n',
      "supabase/migrations/1.sql": "create policy p on public.notes for select using (true);\n",
    };
    const units = await buildUnits(memFiles(files), []);
    expect(units.some((u) => u.file === "app/api/notes/[id]/route.ts" && u.kind === "handler")).toBe(true);
    expect(units.some((u) => u.file === "api.py" && u.framework === "FastAPI")).toBe(true);
    expect(units.some((u) => u.kind === "sql")).toBe(true);
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
