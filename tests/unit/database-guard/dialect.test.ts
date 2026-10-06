import { describe, expect, it } from "vitest";
import { agent, isMysqlOnly } from "../../../src/agents/database-guard/index.js";
import { memContext } from "../../helpers/memfs.js";

// Real-corpus regression: a TiDB (MySQL) schema raised 34 DB-001 and 16 DB-015 — RLS does not exist there.
const mysqlSchema =
  "SET FOREIGN_KEY_CHECKS = 0;\nCREATE TABLE Users (\n  id INT AUTO_INCREMENT PRIMARY KEY,\n  email VARCHAR(255)\n) ENGINE=InnoDB;\n";
const mysqlView = "CREATE VIEW vw_users AS SELECT id, email FROM Users;\n";
const pgTable = "create table public.notes (id uuid primary key default gen_random_uuid(), body text);\n";

const SUPABASE_PKG = { "package.json": '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}' };
const ruleIds = async (files: Record<string, string>) => (await agent.run(memContext(files))).map((f) => f.ruleId);

describe("SQL dialect gate", () => {
  it("skips RLS rules for a MySQL/TiDB schema, including marker-free files beside it", async () => {
    expect(await ruleIds({ "database/01_schema.sql": mysqlSchema, "database/03_views.sql": mysqlView })).toEqual([]);
  });

  it("control: the same tables in Postgres still raise DB-001", async () => {
    expect(await ruleIds({ "database/01_schema.sql": pgTable, ...SUPABASE_PKG })).toContain("DB-001");
  });

  it("control: any Postgres marker in the project keeps the analysis on", async () => {
    expect(isMysqlOnly([{ content: mysqlSchema }, { content: pgTable }])).toBe(false);
    expect(await ruleIds({ "database/01.sql": mysqlSchema, "database/02.sql": pgTable, ...SUPABASE_PKG })).toContain("DB-001");
  });

  it("control: a Supabase project is never treated as MySQL", async () => {
    const files = { "supabase/config.toml": "[api]\nenabled = true\n", "supabase/migrations/001.sql": "create table public.t (id int);\n" };
    expect(await ruleIds(files)).toContain("DB-001");
  });

  it("MySQL `DELIMITER $$` procedures are not mistaken for Postgres dollar quoting", () => {
    const proc = "DELIMITER $$\nCREATE PROCEDURE sp_x() BEGIN SELECT 1; END$$\nDELIMITER ;\n";
    expect(isMysqlOnly([{ content: mysqlSchema }, { content: proc }])).toBe(true);
    const pgFn = "create function f() returns int as $$ select 1 $$ language sql;";
    expect(isMysqlOnly([{ content: mysqlSchema }, { content: pgFn }])).toBe(false);
  });

  it("does not treat plain SQL with no MySQL markers as MySQL", () => {
    expect(isMysqlOnly([{ content: "create table t (id int);" }])).toBe(false);
  });
});

// Code-review regressions: Supabase projects must never be skipped by the gate.
describe("Supabase evidence beyond package.json", () => {
  const table = "create table public.notes (id uuid primary key, body text);\n";
  it.each([
    ["Python requirements", { "requirements.txt": "flask\nsupabase==2.4.0\n" }],
    ["Deno", { "deno.json": '{"imports":{"sb":"npm:@supabase/supabase-js@2"}}' }],
    ["Flutter", { "pubspec.yaml": "dependencies:\n  supabase_flutter: ^2.0.0\n" }],
    ["env keys", { ".env.local": "NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\n", "package.json": '{"dependencies":{"drizzle-orm":"1"}}' }],
  ])("%s", async (_name, extra) => {
    expect(await ruleIds({ "database/schema.sql": table, ...extra })).toContain("DB-001");
  });

  it("a word in a SQL comment never makes a supabase/ migration MySQL", async () => {
    expect(await ruleIds({ "supabase/migrations/1.sql": `-- unsigned urls, AUTO_INCREMENT notes\n${table}` })).toContain("DB-001");
  });

  it("no evidence either way: the SQL is still analysed", async () => {
    expect(await ruleIds({ "db/schema.sql": table })).toContain("DB-001");
  });

  it.each([
    ["Drizzle", { "package.json": '{"dependencies":{"drizzle-orm":"0.30.0","postgres":"3"}}' }],
    ["pg", { "package.json": '{"dependencies":{"pg":"8"}}' }],
    ["SQLAlchemy", { "requirements.txt": "sqlalchemy>=2\npsycopg2-binary\n" }],
  ])("server-only %s project without Supabase is skipped", async (_name, extra) => {
    expect(await ruleIds({ "drizzle/0001.sql": table, ...extra })).toEqual([]);
  });
});
