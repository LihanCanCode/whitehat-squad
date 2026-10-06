import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { memContext } from "../../helpers/memfs.js";

const SUPABASE_PKG = { "package.json": '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}' };
async function scan(files: Record<string, string>) {
  return agent.run(memContext(files));
}
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

describe("agent metadata", () => {
  it("is database-guard", () => {
    expect(agent.id).toBe("database-guard");
    expect(agent.modes).toContain("static");
  });
  it("returns nothing for an empty project", async () => {
    expect(await scan({})).toEqual([]);
  });
});

describe("DB-001 table without RLS", () => {
  it("flags a public table that never enables RLS", async () => {
    const f = await scan({
      "supabase/migrations/001.sql": "create table public.notes (id uuid primary key, user_id uuid, body text);",
    });
    expect(ids(f)).toEqual(["DB-001"]);
    const hit = f[0]!;
    expect(hit.agentId).toBe("database-guard");
    expect(hit.severity).toBe("critical");
    expect(hit.cwe).toBe("CWE-862");
    expect(hit.evidence[0]?.file).toBe("supabase/migrations/001.sql");
    expect(hit.evidence[0]?.line).toBe(1);
    expect(hit.fix.sql).toContain("ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;");
    expect(hit.fix.sql).toContain("auth.uid()) = user_id");
    expect(hit.fix.agentPrompt.length).toBeGreaterThan(40);
    expect(hit.fix.references.some((r) => r.includes("supabase.com/docs"))).toBe(true);
    expect(hit.explanation.toLowerCase()).toContain("anyone");
  });

  it("defaults to the public schema and caps evidence at 200 chars", async () => {
    const cols = Array.from({ length: 60 }, (_, i) => `column_number_${i} text`).join(", ");
    const f = await scan({ "schema.sql": `CREATE TABLE todos (id int, ${cols});`, ...SUPABASE_PKG });
    expect(ids(f)).toEqual(["DB-001"]);
    expect(f[0]!.evidence[0]!.snippet.length).toBeLessThanOrEqual(200);
  });

  it("accepts RLS enabled in a later migration (quoted, case-insensitive)", async () => {
    const f = await scan({
      "supabase/migrations/001.sql": 'CREATE TABLE IF NOT EXISTS "public"."Notes" (id int);',
      "supabase/migrations/002.sql": '-- turn it on\nalter table only public.notes ENABLE ROW LEVEL SECURITY;',
    });
    expect(ids(f)).toEqual(["DB-002"]);
  });

  it("flags again when RLS is later disabled", async () => {
    const f = await scan({
      "supabase/migrations/001.sql":
        "create table a (id int); alter table a enable row level security; alter table a disable row level security;",
    });
    expect(ids(f)).toContain("DB-001");
  });

  it("ignores commented-out, non-public, temp, dropped and dollar-quoted tables", async () => {
    const f = await scan({
      "supabase/a.sql": "-- create table public.x (id int);\n/* create table public.y (id int); */",
      "supabase/b.sql": "create table private.secrets (id int); create temp table t (id int);",
      "supabase/c.sql": "create table public.gone (id int); drop table if exists public.gone;",
      "supabase/d.sql": "create function f() returns void as $$ begin create table public.fake (id int); end $$ language plpgsql set search_path = '';",
    });
    expect(f).toEqual([]);
  });

  it("scans db/*.sql and schema.sql but not unrelated sql files", async () => {
    const f = await scan({
      "db/init.sql": "create table public.a (id int);",
      "other/x.sql": "create table public.b (id int);",
      "node_modules/pkg/supabase/z.sql": "create table public.c (id int);",
      ...SUPABASE_PKG,
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence[0]!.file).toBe("db/init.sql");
  });

  it("never crashes on garbage", async () => {
    const f = await scan({
      "supabase/g.sql": "create table (((; ;;; )) 'unterminated\ncreate policy on; alter table; grant; $$ open",
    });
    expect(Array.isArray(f)).toBe(true);
  });
});

describe("DB-002 RLS with zero policies", () => {
  it("flags enabled RLS without any policy", async () => {
    const f = await scan({
      "supabase/m.sql": "create table public.t (id int); alter table public.t enable row level security;",
    });
    expect(ids(f)).toEqual(["DB-002"]);
    expect(["low", "medium"]).toContain(f[0]!.severity);
  });

  it("is quiet when a policy exists", async () => {
    const f = await scan({
      "supabase/m.sql": `create table public.t (id int, user_id uuid);
        alter table public.t enable row level security;
        create policy "own" on public.t for all to authenticated using (auth.uid() = user_id);`,
    });
    expect(f).toEqual([]);
  });
});

describe("DB-003 permissive policies", () => {
  const base = (tbl: string, policy: string) => ({
    "supabase/m.sql": `create table public.${tbl} (id int, user_id uuid);
      alter table public.${tbl} enable row level security; ${policy}`,
  });

  it("flags USING (true) for anon on user data: high when private columns are exposed", async () => {
    const f = await scan({ "supabase/migrations/1.sql": 'create table public.profiles (id uuid primary key, user_id uuid, email text);\nalter table public.profiles enable row level security;\ncreate policy "all" on public.profiles for select to anon using (true);' });
    expect(ids(f)).toEqual(["DB-003"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.explanation).toContain("It exposes email");
    expect(f[0]!.fix.sql).toContain("DROP POLICY");
  });

  it("read-only open policy without private columns is medium and says it may be deliberate (public-repo study)", async () => {
    const f = await scan(base("profiles", 'create policy "all" on public.profiles for select to anon using (true);'));
    expect(f[0]).toMatchObject({ ruleId: "DB-003", severity: "medium", confidence: "medium" });
    expect(f[0]!.explanation).toContain("fine if every row and column here is meant to be public");
  });

  it("flags WITH CHECK (true) for authenticated and default PUBLIC role", async () => {
    const a = await scan(base("messages", 'create policy "w" on public.messages for insert to authenticated with check ((true));'));
    expect(ids(a)).toEqual(["DB-003"]);
    const b = await scan(base("messages", 'create policy "w" on public.messages for all using (true);'));
    expect(ids(b)).toEqual(["DB-003"]);
  });

  it("ignores reference-data tables and service_role", async () => {
    const f = await scan({
      "supabase/m.sql": `create table public.countries (id int, name text);
        alter table public.countries enable row level security;
        create policy "read" on public.countries for select using (true);`,
    });
    expect(f).toEqual([]);
    const g = await scan(base("profiles", 'create policy "svc" on public.profiles to service_role using (true);'));
    expect(g).toEqual([]);
  });

  it("accepts ownership checks", async () => {
    const f = await scan(base("profiles", 'create policy "own" on public.profiles using ((select auth.uid()) = user_id);'));
    expect(f).toEqual([]);
  });
});

describe("DB-004 policy never uses auth.uid()", () => {
  it("flags a write policy on an owned table that ignores the caller", async () => {
    const f = await scan({
      "supabase/m.sql": `create table public.posts (id int, user_id uuid, published boolean);
        alter table public.posts enable row level security;
        create policy "pub" on public.posts for update to authenticated using (published = true);`,
    });
    expect(ids(f)).toEqual(["DB-004"]);
    expect(f[0]!.severity).toBe("medium");
  });

  it("does not flag a SELECT policy that deliberately shares published rows", async () => {
    const f = await scan({
      "supabase/m.sql": `create table public.posts (id int, user_id uuid, published boolean);
        alter table public.posts enable row level security;
        create policy "pub" on public.posts for select to authenticated using (published = true);`,
    });
    expect(ids(f)).toEqual([]);
  });

  it("sees columns added later and accepts auth.jwt()", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.posts (id int); alter table public.posts enable row level security;
        alter table public.posts add column if not exists owner_id uuid;
        create policy "p" on public.posts using (published);`,
      "supabase/b.sql": `create table public.docs (id int, owner uuid); alter table public.docs enable row level security;
        create policy "p" on public.docs using ((auth.jwt() ->> 'sub')::uuid = owner);`,
    });
    expect(ids(f)).toEqual(["DB-004"]);
    expect(f[0]!.evidence[0]!.file).toBe("supabase/a.sql");
  });
});

describe("DB-005 SECURITY DEFINER", () => {
  it("flags a definer function without search_path", async () => {
    const f = await scan({
      "supabase/f.sql": `create or replace function public.make_admin(uid uuid) returns void
        language plpgsql security definer as $$ begin -- set search_path = public
        update profiles set admin = true where id = uid; end; $$;`,
    });
    // DB-014 (definer function callable by API roles) also fires now; this test is about DB-005.
    const only = f.filter((x) => x.ruleId === "DB-005");
    expect(ids(only)).toEqual(["DB-005"]);
    expect(only[0]!.severity).toBe("high");
    expect(only[0]!.fix.sql).toContain("SET search_path");
  });

  it("accepts SET search_path inline or via ALTER FUNCTION", async () => {
    const f = await scan({
      "supabase/f.sql": `create function public.a() returns void language sql security definer set search_path = '' as $$ select 1 $$;
        create function public.b() returns void language sql security definer as $$ select 1 $$;
        alter function public.b() set search_path = public;
        create function public.c() returns void language sql security invoker as $ select 1 $;`,
    });
    // DB-014 legitimately fires for the definer functions a and b (not revoked); DB-005 must not.
    expect(f.filter((x) => x.ruleId === "DB-005")).toEqual([]);
  });
});

describe("DB-006 anon grants", () => {
  it("flags write grants to anon", async () => {
    const f = await scan({
      "supabase/g.sql": `grant all on public.notes to anon;
        grant insert, update on table public.notes to authenticated, anon;
        grant all on all tables in schema public to anon;
        alter default privileges in schema public grant all on tables to anon;`,
    });
    expect(ids(f)).toEqual(["DB-006", "DB-006", "DB-006", "DB-006"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.fix.sql).toContain("REVOKE");
  });

  it("ignores select-only, schema usage, functions and other roles", async () => {
    const f = await scan({
      "supabase/g.sql": `grant select on public.notes to anon;
        grant usage on schema public to anon;
        grant all on function public.f() to anon;
        grant all on public.notes to authenticated;`,
    });
    expect(f).toEqual([]);
  });
});

describe("DB-007 public storage buckets", () => {
  it("flags public upload buckets via insert and update", async () => {
    const f = await scan({
      "supabase/s.sql": `insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
        update storage.buckets set public = true where id = 'user-uploads';`,
    });
    expect(ids(f)).toEqual(["DB-007", "DB-007"]);
    expect(f[0]!.severity).toBe("medium");
    expect(f.map((x) => x.title).join()).toContain("avatars");
  });

  it("ignores private buckets and buckets made private later", async () => {
    const f = await scan({
      "supabase/a.sql": `insert into storage.buckets (id, name, public) values ('docs', 'docs', false);
        insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);`,
      "supabase/b.sql": "update storage.buckets set public = false where id = 'avatars';",
    });
    expect(f).toEqual([]);
  });
});
