import { promises as fs } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runReview } from "../../../src/review/pipeline.js";
import type { CachedUnit, ReviewCache } from "../../../src/review/pipeline.js";
import { hunterPrompt } from "../../../src/review/prompts.js";
import { resolveClaudeExecutable } from "../../../src/review/provider.js";
import { matchQuote, shownLines, verifyQuotes } from "../../../src/review/quotes.js";
import { buildUnits, envSecrets, localImports, redactSecrets } from "../../../src/review/surface.js";
import { makeTempDir } from "../../helpers/sample-apps.js";
import { memFiles } from "../../helpers/memfs.js";
import { APP, CONFIRMED, FakeProvider, priceHunter } from "./fixtures.js";

// Regressions from the security and code reviews of `whsquad review`.

const route = (imports: string, body = "return Response.json({});") =>
  `${imports}\nexport async function POST(req: Request) {\n  ${body}\n}\n`;

describe("secrets never reach the model", () => {
  it("never sends secret files, even when imported", async () => {
    const files = {
      "service.json": '{"private_key":"-----BEGIN PRIVATE KEY-----abc"}',
      ".npmrc": "//registry.npmjs.org/:_authToken=npm_secretvalue123456",
      "app/api/x/route.ts": route('import sa from "../../../service.json";\nimport cfg from "../../../.npmrc";', "return Response.json({ sa, cfg });"),
    };
    const text = JSON.stringify(await buildUnits(memFiles(files), []));
    expect(text).not.toContain("BEGIN PRIVATE KEY");
    expect(text).not.toContain("npm_secretvalue");
  });

  it("redacts generic secret assignments and SQL passwords, keeps env references", () => {
    expect(redactSecrets('const JWT_SECRET = "hunter2-super-secret";')).toBe('const JWT_SECRET = "[REDACTED]";');
    expect(redactSecrets("password: 'correct horse battery'")).toBe("password: '[REDACTED]'");
    expect(redactSecrets("ALTER ROLE app PASSWORD 's3cr3t-pw';")).toBe("ALTER ROLE app PASSWORD '[REDACTED]';");
    expect(redactSecrets('const apiKey = "process.env.KEY_NAME_HERE";')).toContain("process.env");
  });

  it("scrubs values from .env files out of code that repeats them", async () => {
    const files = { ".env": "INTERNAL_TOKEN=plain-internal-value-42\n", "app/api/x/route.ts": route("", 'const t = "plain-internal-value-42"; return Response.json({ t });') };
    const idx = memFiles(files);
    const text = JSON.stringify(await buildUnits(idx, [], await envSecrets(idx)));
    expect(text).not.toContain("plain-internal-value-42");
  });

  it("redaction and import scanning stay linear on hostile input", () => {
    const hostile = `import${" ".repeat(200_000)}`;
    let t = Date.now();
    localImports("a.ts", hostile, new Set());
    redactSecrets(`password = "${"a".repeat(100_000)}`);
    redactSecrets("token=".repeat(50_000));
    expect(Date.now() - t).toBeLessThan(1500);
    t = Date.now();
    localImports("a.ts", `import x from ${"'".repeat(100_000)}`, new Set());
    expect(Date.now() - t).toBeLessThan(1500);
  });
});

describe("context building", () => {
  it("resolves ESM-style .js imports to .ts files and aliases inside monorepo apps", () => {
    const known = new Set(["src/db.ts", "apps/web/src/lib/auth.ts", "lib/auth.ts"]);
    expect(localImports("src/route.ts", 'import { db } from "./db.js";', known).map((i) => i.file)).toEqual(["src/db.ts"]);
    expect(localImports("apps/web/src/app/x/route.ts", 'import { auth } from "@/lib/auth";', known).map((i) => i.file)).toEqual(["apps/web/src/lib/auth.ts"]);
  });

  it("sends the imports the unit actually uses first", async () => {
    const files = {
      "lib/a.ts": "export const a = 1;\n", "lib/b.ts": "export const b = 1;\n", "lib/c.ts": "export const c = 1;\n", "lib/db.ts": "export const db = 1;\n",
      "app/api/x/route.ts": route('import { a } from "@/lib/a";\nimport { b } from "@/lib/b";\nimport { c } from "@/lib/c";\nimport { db } from "@/lib/db";', "return Response.json(db);"),
    };
    const [u] = await buildUnits(memFiles(files), []);
    expect(u?.related[0]?.file).toBe("lib/db.ts");
  });

  it("keeps duplicate handler labels distinct and marks truncated units", async () => {
    const long = Array.from({ length: 300 }, (_, i) => `  const v${i} = ${i};`).join("\n");
    const files = {
      "server.ts": 'import express from "express";\nconst app = express();\napp.post("/x", (req, res) => { res.send(req.body); });\napp.post("/x", (req, res) => { res.send(req.query); });\n',
      "app/api/big/route.ts": `export async function POST(req: Request) {\n${long}\n  return Response.json({});\n}\n`,
    };
    const units = await buildUnits(memFiles(files), []);
    const ids = units.map((u) => u.id);
    expect(new Set(ids).size).toBe(ids.length);
    const big = units.find((u) => u.file === "app/api/big/route.ts")!;
    expect(big.truncatedLines).toBeGreaterThan(0);
    expect(big.excerpt).toContain("more lines of this unit not shown");
    expect(hunterPrompt(big)).toContain("Only part of this unit is shown");
  });

  it("keeps the SQL unit when one policy file is too large, and names what was left out", async () => {
    const huge = `create policy big on t for select using (true);\n${`-- ${"filler ".repeat(14)}\n`.repeat(900)}`;
    const files = { "supabase/migrations/1_big.sql": huge, "supabase/migrations/2.sql": "create policy p on u for select using (true);\n" };
    const units = await buildUnits(memFiles(files), []);
    const sql = units.find((u) => u.kind === "sql");
    expect(sql?.excerpt).toContain("2.sql");
    expect(sql?.omitted).toEqual(["supabase/migrations/1_big.sql"]);
  });

  it("fences repository data with a random marker the repo cannot predict", async () => {
    const [u] = await buildUnits(memFiles(APP), []);
    const a = hunterPrompt(u!);
    const b = hunterPrompt(u!);
    const marker = (p: string) => /END REPOSITORY DATA ([0-9a-f]+)/.exec(p)?.[1];
    expect(marker(a)).toMatch(/^[0-9a-f]{18}$/);
    expect(marker(a)).not.toBe(marker(b));
  });
});

describe("quote matching", () => {
  it("rejects generic fragments, accepts whole short lines, multi-line quotes, CRLF, and corrects the line", async () => {
    const files = { "app/api/x/route.ts": "export async function POST(req: Request) {\r\n  const id = req.headers.get(\"x-user\");\r\n  return data;\r\n}\r\n" };
    const [u] = await buildUnits(memFiles(files), []);
    const shown = shownLines(u!);
    expect(matchQuote({ file: "app/api/x/route.ts", line: 3, quote: "return" }, shown)).toBeUndefined();
    expect(matchQuote({ file: "app/api/x/route.ts", line: 3, quote: "return data;" }, shown)).toBe(3);
    expect(matchQuote({ file: "app/api/x/route.ts", line: 1, quote: 'const id = req.headers.get("x-user");' }, shown)).toBe(2);
    expect(matchQuote({ file: "app/api/x/route.ts", line: 2, quote: 'const id = req.headers.get("x-user");\n  return data;' }, shown)).toBe(2);
    expect(verifyQuotes([{ file: "app/api/x/route.ts", line: 1, quote: 'const id = req.headers.get("x-user");' }], shown)?.[0]?.line).toBe(2);
  });
});

describe("pipeline robustness", () => {
  class MemCache implements ReviewCache {
    readonly map = new Map<string, CachedUnit>();
    get(k: string) { return this.map.get(k); }
    set(v: CachedUnit) { this.map.set(v.key, v); }
  }

  it("never caches a unit whose validator reply was unusable, and does not count it as rejected", async () => {
    const cache = new MemCache();
    const r = await runReview(await buildUnits(memFiles(APP), []), new FakeProvider(priceHunter, () => ({ junk: 1 })), { target: ".", maxCalls: 10, cache });
    const entry = r.ledger.find((l) => l.unit.includes("placeOrder"));
    expect(entry).toMatchObject({ rejected: 0, invalid: 1 });
    expect([...cache.map.values()].some((c) => c.entry.unit.includes("placeOrder"))).toBe(false);
  });

  it("records the unit id on findings so a recheck can find them after lines move", async () => {
    const r = await runReview(await buildUnits(memFiles(APP), []), new FakeProvider(priceHunter, () => CONFIRMED), { target: ".", maxCalls: 10 });
    expect(r.findings[0]?.reviewUnit).toBe("app/actions/orders.ts#placeOrder");
    expect(r.findings[0]?.fix.agentPrompt.startsWith("[AI-generated suggestion")).toBe(true);
  });
});

describe("claude executable resolution", () => {
  it("ignores PATH entries inside the scanned repo and any node_modules/.bin", async () => {
    const repo = await makeTempDir();
    try {
      const bin = path.join(repo, "node_modules", ".bin");
      await fs.mkdir(bin, { recursive: true });
      await fs.writeFile(path.join(bin, "claude.exe"), "");
      await fs.writeFile(path.join(bin, "claude"), "");
      expect(resolveClaudeExecutable({ PATH: bin }, "win32", repo)).toBeUndefined();
      expect(resolveClaudeExecutable({ PATH: bin }, "linux")).toBeUndefined();
    } finally {
      await fs.rm(repo, { recursive: true, force: true });
    }
  });
});

describe("transient CLI failures", () => {
  it("retries once (counted against the budget), then records an error", async () => {
    const { ProviderError } = await import("../../../src/review/provider.js");
    let failures = 1;
    const flaky = new FakeProvider((prompt) => {
      if (prompt.includes("placeOrder") && failures-- > 0) throw new ProviderError("claude timed out after 360 s");
      return priceHunter(prompt);
    });
    const r = await runReview(await buildUnits(memFiles(APP), []), flaky, { target: ".", maxCalls: 10, concurrency: 1 });
    expect(r.findings).toHaveLength(1);
    expect(r.calls).toBe(4);
    const alwaysDown = new FakeProvider(() => { throw new ProviderError("claude timed out after 360 s"); });
    const down = await runReview(await buildUnits(memFiles(APP), []), alwaysDown, { target: ".", maxCalls: 10, concurrency: 1 });
    expect(down.ledger.every((l) => l.status === "error")).toBe(true);
    expect(alwaysDown.requests).toHaveLength(4);
  });
});

describe("database grounding", () => {
  it("adds the RLS and policy lines of every table a handler (or its helper) queries, quotable by real line", async () => {
    const files = {
      ...APP,
      "supabase/migrations/1.sql": "create table public.notes (id uuid, user_id uuid);\nalter table public.notes enable row level security;\ncreate policy \"open\" on public.notes for select using (true);\ncreate table public.other (id int);\n",
    };
    const units = await buildUnits(memFiles(files), []);
    const notes = units.find((u) => u.file === "app/api/notes/[id]/route.ts")!;
    const sql = notes.related.find((r) => r.file === "supabase/migrations/1.sql");
    expect(sql?.excerpt).toContain('3 | create policy "open" on public.notes for select using (true);');
    expect(sql?.excerpt).not.toContain("public.other");
    expect(hunterPrompt(notes)).toContain("(database access rules)");
    expect(matchQuote({ file: "supabase/migrations/1.sql", line: 3, quote: "create policy \"open\" on public.notes" }, shownLines(notes))).toBe(3);
  });
});
