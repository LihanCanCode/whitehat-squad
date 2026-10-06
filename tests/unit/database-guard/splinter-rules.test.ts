import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { memContext } from "../../helpers/memfs.js";

const scan = (files: Record<string, string>) => agent.run(memContext(files));
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();
const tbl = (name: string, cols: string, policies = "") =>
  `create table public.${name} (${cols}); alter table public.${name} enable row level security;\n${policies}`;

interface Complete {
  fix: { agentPrompt: string; references: readonly string[]; sql?: string; config?: string };
  evidence: readonly { file?: string; line?: number }[];
  explanation: string;
  cwe?: string;
}
function expectComplete(f: Complete): void {
  expect(f.explanation.length).toBeGreaterThan(60);
  expect(f.fix.agentPrompt.length).toBeGreaterThan(40);
  expect(f.fix.references.length).toBeGreaterThan(0);
  expect(f.fix.sql ?? f.fix.config).toBeTruthy();
  expect(f.evidence[0]?.file).toBeTruthy();
  expect(f.evidence[0]?.line).toBeGreaterThan(0);
  expect(f.cwe).toMatch(/^CWE-/);
}

describe("DB-012 user_metadata in authorization", () => {
  it("flags user_metadata in a policy as critical", async () => {
    const f = await scan({
      "supabase/a.sql": tbl("reports", "id int", `create policy "adm" on public.reports for all to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');`),
    });
    expect(ids(f)).toEqual(["DB-012"]);
    expect(f[0]!.severity).toBe("critical");
    expectComplete(f[0]!);
    expect(f[0]!.fix.sql).toContain("app_metadata");
  });
  it("flags raw_user_meta_data in a SECURITY DEFINER role check", async () => {
    const f = await scan({
      "supabase/a.sql": `create function public.is_admin() returns boolean language sql security definer set search_path = ''
        as $$ select (select raw_user_meta_data ->> 'role' from auth.users where id = auth.uid()) = 'admin' $$;
        revoke all on function public.is_admin() from public, anon, authenticated;`,
    });
    expect(ids(f)).toEqual(["DB-012"]);
  });
  it("never flags app_metadata, nor a trigger that only copies a display name", async () => {
    const f = await scan({
      "supabase/a.sql": `${tbl("reports", "id int", `create policy "adm" on public.reports for all to authenticated using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');`)}
        create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
        begin insert into public.reports (id) values (new.id); perform new.raw_user_meta_data ->> 'full_name'; return new; end $$;`,
    });
    expect(f).toEqual([]);
  });
});

describe("DB-013 self privilege escalation", () => {
  const profiles = (extra: string, cols = "id uuid primary key references auth.users(id), name text, role text") =>
    tbl("profiles", cols, `create policy "own" on public.profiles for update to authenticated using ((select auth.uid()) = id);\n${extra}`);
  it("flags a role column writable through an own-row UPDATE policy as high", async () => {
    const f = await scan({ "supabase/a.sql": profiles("") });
    expect(ids(f)).toEqual(["DB-013"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.explanation).toContain("role");
    expectComplete(f[0]!);
  });
  it("credits / plan are medium", async () => {
    const f = await scan({ "supabase/a.sql": profiles("", "id uuid primary key references auth.users(id), credits int") });
    expect(ids(f)).toEqual(["DB-013"]);
    expect(f[0]!.severity).toBe("medium");
  });
  it.each([
    ["table-level revoke", "revoke update on public.profiles from authenticated;"],
    ["column grant that excludes it", "revoke update on public.profiles from authenticated; grant update (name) on public.profiles to authenticated;"],
    ["BEFORE UPDATE trigger mentioning it", "create function public.guard_role() returns trigger language plpgsql set search_path = '' as $$ begin new.role := old.role; return new; end $$;\ncreate trigger guard before update on public.profiles for each row execute function public.guard_role();"],
  ])("is quiet with column protection: %s", async (_n, extra) => {
    expect(ids(await scan({ "supabase/a.sql": profiles(extra) }))).toEqual([]);
  });
  it("is quiet when the column only resembles a sensitive name", async () => {
    expect(await scan({ "supabase/a.sql": profiles("", "id uuid primary key references auth.users(id), name text, enrolled text") })).toEqual([]);
  });
  it("is quiet when the policy is a SELECT policy (control)", async () => {
    const f = await scan({
      "supabase/a.sql": tbl("profiles", "id uuid primary key references auth.users(id), role text", `create policy "r" on public.profiles for select to authenticated using ((select auth.uid()) = id);`),
    });
    expect(f).toEqual([]);
  });
});

describe("DB-014 SECURITY DEFINER executable by API roles", () => {
  const fn = (name = "promote", args = "uid uuid", body = "update public.t set a = 1 where id = uid", ret = "void") =>
    `create function public.${name}(${args}) returns ${ret} language plpgsql security definer set search_path = '' as $$ begin ${body}; end $$;`;
  it("flags and uses the stronger wording for an unchecked uuid parameter", async () => {
    const f = await scan({ "supabase/a.sql": fn() });
    expect(ids(f)).toEqual(["DB-014"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.explanation.toLowerCase()).toContain("any user id");
    expectComplete(f[0]!);
  });
  it("is quiet when revoked, for triggers, invoker functions and other schemas", async () => {
    const f = await scan({
      "supabase/a.sql": `${fn("a")} revoke execute on function public.a(uuid) from public, anon, authenticated;
        ${fn("b", "", "return new", "trigger")}
        create function public.c() returns void language sql security invoker as $$ select 1 $$;
        create function private.d() returns void language sql security definer set search_path = '' as $$ select 1 $$;`,
    });
    expect(f).toEqual([]);
  });
  it("a blanket revoke on all functions in the schema clears it", async () => {
    const f = await scan({ "supabase/a.sql": `${fn("a")} revoke execute on all functions in schema public from public, anon, authenticated;` });
    expect(f).toEqual([]);
  });
});

describe("DB-015 views without security_invoker", () => {
  it("flags a public view as high", async () => {
    const f = await scan({ "supabase/a.sql": "create view public.v as select id from public.t;" });
    expect(ids(f)).toEqual(["DB-015"]);
    expect(f[0]!.severity).toBe("high");
    expectComplete(f[0]!);
  });
  it("is critical when it selects from auth.users", async () => {
    const f = await scan({ "supabase/a.sql": "create or replace view public.people as select id, email from auth.users;" });
    expect(f.find((x) => x.ruleId === "DB-015")!.severity).toBe("critical");
  });
  it("is quiet with security_invoker, other schemas, or a revoke from API roles", async () => {
    const f = await scan({
      "supabase/a.sql": `create view public.a with (security_invoker = true) as select 1 as x;
        create view public.b with (security_invoker=on) as select 1 as x;
        create view private.c as select 1 as x;
        create view public.d as select 1 as x; revoke select on public.d from anon, authenticated;`,
    });
    expect(f).toEqual([]);
  });
});

describe("DB-016 policy on a table without RLS", () => {
  it("flags the unprotected table whose author wrote policies", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.docs (id int, user_id uuid);
        create policy "own" on public.docs for all to authenticated using ((select auth.uid()) = user_id);`,
    });
    expect(ids(f)).toEqual(["DB-001", "DB-016"]);
    const hit = f.find((x) => x.ruleId === "DB-016")!;
    expect(hit.severity).toBe("high");
    expect(hit.explanation.toLowerCase()).toContain("not enforced");
    expectComplete(hit);
  });
  it("is quiet when RLS is enabled, or the table is not in the repo", async () => {
    const a = await scan({ "supabase/a.sql": tbl("docs", "id int, user_id uuid", `create policy "own" on public.docs using ((select auth.uid()) = user_id);`) });
    expect(a).toEqual([]);
    const b = await scan({ "supabase/a.sql": `create policy "own" on public.dash using ((select auth.uid()) = user_id);` });
    expect(b).toEqual([]);
  });
});

describe("DB-017 any signed-in user policies", () => {
  it.each(["auth.uid() is not null", "(select auth.uid()) is not null", "auth.role() = 'authenticated'"])("flags %s", async (cond) => {
    const f = await scan({ "supabase/a.sql": tbl("notes", "id int, user_id uuid", `create policy "any" on public.notes for select to authenticated using (${cond});`) });
    expect(ids(f)).toEqual(["DB-017"]);
    expect(f[0]!.severity).toBe("medium");
    expectComplete(f[0]!);
  });
  it("is quiet for own-row checks, tables without an owner column and combined conditions", async () => {
    const f = await scan({
      "supabase/a.sql": `${tbl("notes", "id int, user_id uuid", `create policy "own" on public.notes using ((select auth.uid()) = user_id);`)}
        ${tbl("countries", "id int, name text", `create policy "any" on public.countries for select to authenticated using (auth.uid() is not null);`)}
        ${tbl("tasks", "id int, user_id uuid", `create policy "c" on public.tasks for select to authenticated using (auth.uid() is not null and user_id = auth.uid());`)}`,
    });
    expect(f).toEqual([]);
  });
});

describe("DB-018 storage.objects policies", () => {
  const bucket = (pub: boolean) => `insert into storage.buckets (id, name, public) values ('photos', 'photos', ${pub});`;
  it("flags a SELECT policy that only checks bucket_id on a public bucket as medium listing exposure", async () => {
    const f = await scan({
      "supabase/a.sql": `${bucket(true)} create policy "list" on storage.objects for select using (bucket_id = 'photos');`,
    });
    const hit = f.filter((x) => x.ruleId === "DB-018");
    expect(hit).toHaveLength(1);
    expect(hit[0]!.severity).toBe("medium");
    expectComplete(hit[0]!);
  });
  it("flags write policies without an owner check as high", async () => {
    const f = await scan({
      "supabase/a.sql": `${bucket(false)} create policy "up" on storage.objects for insert to authenticated with check (bucket_id = 'photos');
        create policy "del" on storage.objects for delete to authenticated using (bucket_id = 'photos' and auth.role() = 'authenticated');`,
    });
    const hits = f.filter((x) => x.ruleId === "DB-018");
    expect(hits).toHaveLength(2);
    expect(hits.every((h) => h.severity === "high")).toBe(true);
  });
  it("is quiet for owner-scoped policies and private-bucket SELECTs", async () => {
    const f = await scan({
      "supabase/a.sql": `${bucket(false)} create policy "mine" on storage.objects for insert to authenticated with check (bucket_id = 'photos' and (select auth.uid())::text = (storage.foldername(name))[1]);
        create policy "priv" on storage.objects for select using (bucket_id = 'photos');`,
    });
    expect(f).toEqual([]);
  });
  it("our own private-bucket fix SQL is not flagged", async () => {
    const first = await scan({ "supabase/a.sql": "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);" });
    const fixSql = first.find((x) => x.ruleId === "DB-007")!.fix.sql!;
    const f = await scan({ "supabase/a.sql": fixSql });
    expect(f).toEqual([]);
  });
});

describe("DB-019 sensitive columns exposed", () => {
  it("flags secret-like columns behind a USING (true) read policy", async () => {
    const f = await scan({
      "supabase/a.sql": tbl("integrations", "id int, api_key text, name text", `create policy "r" on public.integrations for select to anon, authenticated using (true);`),
    });
    const hit = f.find((x) => x.ruleId === "DB-019")!;
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("high");
    expect(hit.explanation).toContain("api_key");
    expectComplete(hit);
  });
  it("is quiet for owner-scoped policies and harmless column names", async () => {
    const f = await scan({
      "supabase/a.sql": `${tbl("secrets_a", "id int, user_id uuid, refresh_token text", `create policy "o" on public.secrets_a for select to authenticated using ((select auth.uid()) = user_id);`)}
        ${tbl("catalog", "id int, tokenizer_name text, passwords_policy text", `create policy "r" on public.catalog for select using (true);`)}`,
    });
    expect(ids(f)).toEqual([]);
  });
});

const SUPABASE_PKG = { "package.json": '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}' };
describe("SQL discovery", () => {
  it.each([
    "prisma/migrations/20240101_init/migration.sql",
    "drizzle/0001_init.sql",
    "migrations/001_init.sql",
    "db/migrations/001_init.sql",
    "sql/init.sql",
    "database/init.sql",
    "apps/api/prisma/migrations/1/migration.sql",
  ])("scans %s", async (p) => {
    const f = await scan({ [p]: "create table public.a (id int);", ...SUPABASE_PKG });
    expect(ids(f)).toEqual(["DB-001"]);
  });
  it("plain Postgres behind an ORM (no Supabase anywhere) raises no RLS findings", async () => {
    const orm = { "package.json": '{"dependencies":{"drizzle-orm":"0.30.0"}}' };
    expect(await scan({ "drizzle/0001_init.sql": "create table public.a (id int);", ...orm })).toEqual([]);
  });
  it("an @supabase dependency in a nested workspace package.json counts", async () => {
    const f = await scan({ "drizzle/0001_init.sql": "create table public.a (id int);", "apps/web/package.json": SUPABASE_PKG["package.json"] });
    expect(ids(f)).toEqual(["DB-001"]);
  });
  it("ignores node_modules and unrelated folders", async () => {
    const f = await scan({ "node_modules/x/migrations/a.sql": "create table public.a (id int);", "docs/a.sql": "create table public.b (id int);" });
    expect(f).toEqual([]);
  });
  it("orders migrations deterministically (numeric prefixes sort naturally)", async () => {
    const f = await scan({
      "supabase/migrations/10_drop.sql": 'drop policy "open" on public.posts;',
      "supabase/migrations/2_init.sql": `create table public.posts (id int, user_id uuid); alter table public.posts enable row level security;
create policy "open" on public.posts for select to anon using (true);`,
    });
    expect(ids(f)).toEqual(["DB-002"]);
  });
});
