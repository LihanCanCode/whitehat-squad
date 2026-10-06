import { describe, expect, it } from "vitest";
import { express, only, route, scanOne } from "./helpers.js";

const PG = `const { Pool } = require("pg");\nconst pool = new Pool();`;

describe("INJ-001 SQL injection from request data", () => {
  it("flags a template query built from req.params (critical, CWE-89, with fix + prompt)", async () => {
    const code = express("  const { id } = req.params;\n  const r = await pool.query(`SELECT * FROM users WHERE id = ${id}`);\n  res.json(r.rows);", PG);
    const f = only(await scanOne(code), "INJ-001");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-89", agentId: "injection-hunter" });
    expect(f[0]?.evidence[0]?.file).toBe("server.js");
    expect(f[0]?.evidence[0]?.line).toBe(6);
    expect(f[0]?.evidence[0]?.snippet).toContain("pool.query");
    expect(f[0]?.fix.agentPrompt).toContain("server.js");
    expect(f[0]?.fix.agentPrompt).toContain("line 6");
    expect(f[0]?.fix.patch?.diff).toContain("$1");
    expect(f[0]?.fix.references.some((r) => r.includes("SQL_Injection_Prevention"))).toBe(true);
    expect(f[0]?.explanation.length).toBeGreaterThan(80);
  });
  it("flags string concatenation and a query variable built with +=", async () => {
    const concat = express('  const r = await pool.query("SELECT * FROM t WHERE name = \'" + req.query.name + "\'");', PG);
    expect(only(await scanOne(concat), "INJ-001")).toHaveLength(1);
    const built = express(
      '  const { name } = req.body;\n  let query = "SELECT * FROM t WHERE 1=1";\n  if (name) query += ` AND name = \'${name}\'`;\n  const r = await pool.query(query);',
      PG,
    );
    expect(only(await scanOne(built), "INJ-001")).toHaveLength(1);
  });
  it("flags mysql2 execute, sequelize.query, typeorm query and sqlite prepare templates", async () => {
    for (const call of ["connection.execute", "sequelize.query", "dataSource.query", "db.prepare"]) {
      const code = express(`  const r = await ${call}(\`SELECT * FROM t WHERE a = '\${req.body.a}'\`);`);
      expect(only(await scanOne(code), "INJ-001"), call).toHaveLength(1);
    }
  });
  it("flags knex raw / whereRaw / orderByRaw templates and sql.raw", async () => {
    for (const call of ["knex.raw", "db('t').whereRaw", "db('t').orderByRaw", "sql.raw"]) {
      const code = express(`  const r = await ${call}(\`name = '\${req.query.q}'\`);`);
      expect(only(await scanOne(code), "INJ-001"), call).toHaveLength(1);
    }
    expect(only(await scanOne(express("  await sql.raw(req.query.order);")), "INJ-001")).toHaveLength(1);
  });
  it("works in a Next.js route handler with searchParams", async () => {
    const code = route('  const id = new URL(req.url).searchParams.get("id");\n  const r = await db.query(`SELECT * FROM t WHERE id = ${id}`);\n  return Response.json(r);', "", "GET");
    expect(only(await scanOne(code, "app/api/t/route.ts"), "INJ-001")).toHaveLength(1);
  });

  it("does not flag parameterized queries; still flags an interpolated column next to $1", async () => {
    const safe = express('  const r = await pool.query("SELECT * FROM t WHERE id = $1", [req.params.id]);', PG);
    expect(only(await scanOne(safe), "INJ-001")).toEqual([]);
    const mixed = express("  const r = await pool.query(`SELECT * FROM t WHERE id = $1 ORDER BY ${req.query.sort}`, [req.params.id]);", PG);
    expect(only(await scanOne(mixed), "INJ-001")).toHaveLength(1);
  });
  it("does not flag tagged templates; still flags the untagged one", async () => {
    const tagged = express("  const r = await db.query(sql`SELECT * FROM t WHERE id = ${req.params.id}`);");
    expect(only(await scanOne(tagged), "INJ-001")).toEqual([]);
    const plain = express("  const r = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);");
    expect(only(await scanOne(plain), "INJ-001")).toHaveLength(1);
  });
  it("does not flag knex bindings or sequelize replacements; still flags raw interpolation", async () => {
    const safe = express(
      '  await knex.raw("select ?? from t where id = ?", [req.query.col, req.params.id]);\n  await db("t").whereRaw("id = ?", [req.params.id]);\n  await sequelize.query("select * from t where id = :id", { replacements: { id: req.params.id } });',
    );
    expect(only(await scanOne(safe), "INJ-001")).toEqual([]);
    const raw = express("  await db('t').whereRaw(`id = ${req.params.id}`);");
    expect(only(await scanOne(raw), "INJ-001")).toHaveLength(1);
  });
  it("does not flag Number()-coerced values or UPPER_CASE constant interpolation; still flags the raw value", async () => {
    const safe = express(
      "  const id = Number(req.params.id);\n  const r = await pool.query(`SELECT * FROM ${TABLE} WHERE id = ${id}`);",
      'const TABLE = "users";',
    );
    expect(only(await scanOne(safe), "INJ-001")).toEqual([]);
    const raw = express("  const id = req.params.id;\n  const r = await pool.query(`SELECT * FROM ${TABLE} WHERE id = ${id}`);", 'const TABLE = "users";');
    expect(only(await scanOne(raw), "INJ-001")).toHaveLength(1);
  });
  it("does not flag a value checked against an allowlist; still flags without the check", async () => {
    const guarded = express(
      "  const sort = req.query.sort;\n  if (!ALLOWED.includes(sort)) return res.sendStatus(400);\n  const r = await pool.query(`SELECT * FROM t ORDER BY ${sort}`);",
      'const ALLOWED = ["name", "created_at"];',
    );
    expect(only(await scanOne(guarded), "INJ-001")).toEqual([]);
    const aliased = express(
      '  const col = ALLOWED.includes(req.query.sort) ? req.query.sort : "name";\n  const r = await pool.query(`SELECT * FROM t ORDER BY ${col}`);',
      'const ALLOWED = ["name", "created_at"];',
    );
    expect(only(await scanOne(aliased), "INJ-001")).toEqual([]);
    const lookup = express("  const r = await pool.query(`SELECT * FROM t ORDER BY ${COLUMNS[req.query.sort]}`);", 'const COLUMNS = { a: "a" };');
    expect(only(await scanOne(lookup), "INJ-001")).toEqual([]);
    const open = express("  const r = await pool.query(`SELECT * FROM t ORDER BY ${req.query.sort}`);");
    expect(only(await scanOne(open), "INJ-001")).toHaveLength(1);
  });
  it("does not flag an anchored-regex validated id", async () => {
    const code = express("  const id = req.params.id;\n  if (!/^\\d+$/.test(id)) return res.sendStatus(400);\n  await pool.query(`SELECT * FROM t WHERE id = ${id}`);");
    expect(only(await scanOne(code), "INJ-001")).toEqual([]);
  });
  it("does not flag non-database .query() receivers or untainted templates", async () => {
    const trpc = express("  const r = await trpc.users.query(req.body);\n  await apollo.query({ query: req.body.q });");
    expect(only(await scanOne(trpc), "INJ-001")).toEqual([]);
    const clean = express('  const table = "users";\n  await pool.query(`SELECT * FROM ${table}`);');
    expect(only(await scanOne(clean), "INJ-001")).toEqual([]);
  });
  it("skips tests, generated, vendor, client and non-JS files", async () => {
    const code = express("  await pool.query(`SELECT * FROM t WHERE id = ${req.params.id}`);");
    expect(await scanOne(code, "src/server.test.js")).toEqual([]);
    expect(await scanOne(code, "node_modules/x/index.js")).toEqual([]);
    expect(await scanOne(`"use client";\n${code}`)).toEqual([]);
    expect(await scanOne(code, "README.md")).toEqual([]);
  });
  it("ignores SQL in comments and strings", async () => {
    const code = express('  // pool.query(`SELECT ${req.params.id}`)\n  const s = "pool.query(`${req.params.id}`)";');
    expect(await scanOne(code)).toEqual([]);
  });
});

describe("INJ-001/INJ-002 Prisma unsafe raw", () => {
  const P = `import { prisma } from "@/lib/db";`;
  it("tainted $queryRawUnsafe is critical INJ-001", async () => {
    const code = route("  const { q } = await req.json();\n  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${q}'`);\n  return Response.json(rows);", P);
    const f = only(await scanOne(code, "app/api/s/route.ts"), "INJ-001");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("critical");
    expect(f[0]?.fix.agentPrompt).toContain("$queryRaw");
  });
  it("non-literal but untainted $executeRawUnsafe is high INJ-002 (medium confidence)", async () => {
    const code = `import { prisma } from "@/lib/db";\nexport async function purge(table: string) {\n  await prisma.$executeRawUnsafe(\`DELETE FROM \${table}\`);\n}\n`;
    const all = await scanOne(code, "src/lib/purge.ts");
    const f = only(all, "INJ-002");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium", cwe: "CWE-89" });
    expect(only(all, "INJ-001")).toEqual([]);
  });
  it("does not flag literal queries with bound values, or tagged $queryRaw", async () => {
    const code = route(
      '  const { id } = await req.json();\n  await prisma.$queryRawUnsafe("SELECT * FROM t WHERE id = $1", id);\n  await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;\n  await prisma.$executeRawUnsafe(`DELETE FROM ${TABLE} WHERE id = $1`, id);',
      P + '\nconst TABLE = "t";',
    );
    expect(await scanOne(code, "app/api/s/route.ts")).toEqual([]);
  });
  it("does not run the untainted rule in scripts/seed paths", async () => {
    const code = "export async function seed(t: string) { await prisma.$executeRawUnsafe(`DELETE FROM ${t}`); }\n";
    expect(await scanOne(code, "scripts/seed.ts")).toEqual([]);
  });
});

describe("INJ-003 Supabase PostgREST filter injection", () => {
  const SB = `import { createClient } from "@supabase/supabase-js";\nconst supabase = createClient("u", "k");`;
  it("flags .or() with a tainted template (medium)", async () => {
    const code = route("  const { q } = await req.json();\n  const { data } = await supabase.from(\"items\").select().or(`name.ilike.%${q}%,description.ilike.%${q}%`);\n  return Response.json(data);", SB);
    const f = only(await scanOne(code, "app/api/search/route.ts"), "INJ-003");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", agentId: "injection-hunter" });
    expect(f[0]?.fix.agentPrompt).toContain("app/api/search/route.ts");
  });
  it("flags .filter() and .textSearch() with tainted templates and concat", async () => {
    const code = route(
      '  const q = new URL(req.url).searchParams.get("q");\n  await supabase.from("a").select().filter("name", "in", `(${q})`);\n  await supabase.from("a").select().textSearch("body", "\'" + q + "\'");',
      SB,
    );
    expect(only(await scanOne(code, "app/api/search/route.ts"), "INJ-003")).toHaveLength(2);
  });
  it("does not flag constant filters, Array.filter or non-supabase files; still flags the real one", async () => {
    const safe = route(
      '  const { q } = await req.json();\n  const xs = items.filter((i) => i.name === q);\n  await supabase.from("a").select().or("a.eq.1,b.eq.2");\n  await supabase.from("a").select().eq("name", q);',
      SB,
    );
    expect(only(await scanOne(safe, "app/api/s/route.ts"), "INJ-003")).toEqual([]);
    const mongo = route("  const { q } = await req.json();\n  await Model.find().or(`${q}`);", `import mongoose from "mongoose";`);
    expect(only(await scanOne(mongo, "app/api/s/route.ts"), "INJ-003")).toEqual([]);
  });
  it("does not flag when the value has its filter separators stripped; still flags the unstripped one", async () => {
    const stripped = route(
      '  const { q } = await req.json();\n  const safe = q.replace(/[,()]/g, "");\n  await supabase.from("a").select().or(`name.ilike.%${safe}%`);',
      SB,
    );
    expect(only(await scanOne(stripped, "app/api/s/route.ts"), "INJ-003")).toEqual([]);
    const raw = route("  const { q } = await req.json();\n  await supabase.from(\"a\").select().or(`name.ilike.%${q}%`);", SB);
    expect(only(await scanOne(raw, "app/api/s/route.ts"), "INJ-003")).toHaveLength(1);
  });
});
