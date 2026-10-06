import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { ownerColumn } from "../../../src/agents/database-guard/fixes.js";
import { buildModel } from "../../../src/agents/database-guard/sql-model.js";
import { analyzeFirebaseRules } from "../../../src/agents/database-guard/firebase-rules.js";
import { memContext } from "../../helpers/memfs.js";

const scan = (files: Record<string, string>) => agent.run(memContext(files));
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

const POSTS = `create table public.posts (id int, user_id uuid, body text);
alter table public.posts enable row level security;
create policy "open" on public.posts for select to anon using (true);`;

describe("bug 1: later statements are applied to the model", () => {
  it("DROP POLICY in a later migration clears DB-003", async () => {
    const f = await scan({
      "supabase/migrations/001.sql": POSTS,
      "supabase/migrations/002.sql": 'drop policy "open" on public.posts;',
    });
    expect(ids(f)).toEqual(["DB-002"]);
  });

  it("our own DB-003 fix SQL clears the finding when applied as migration 002", async () => {
    const first = await scan({ "supabase/migrations/001.sql": POSTS });
    expect(ids(first)).toEqual(["DB-003"]);
    const f = await scan({
      "supabase/migrations/001.sql": POSTS,
      "supabase/migrations/002.sql": first[0]!.fix.sql!,
    });
    expect(f).toEqual([]);
  });

  it("ALTER POLICY replaces the expression", async () => {
    const f = await scan({
      "supabase/migrations/001.sql": POSTS,
      "supabase/migrations/002.sql": 'alter policy "open" on public.posts to authenticated using ((select auth.uid()) = user_id);',
    });
    expect(ids(f)).toEqual([]);
  });

  it("an unrelated drop policy leaves the finding (control)", async () => {
    const f = await scan({
      "supabase/migrations/001.sql": POSTS,
      "supabase/migrations/002.sql": 'drop policy "something else" on public.posts;',
    });
    expect(ids(f)).toEqual(["DB-003"]);
  });

  it("REVOKE clears DB-006; a partial or other-role revoke does not", async () => {
    const grant = "grant all on public.notes to anon;";
    const cleared = await scan({ "supabase/a.sql": grant, "supabase/b.sql": "revoke all on public.notes from anon;" });
    expect(ids(cleared)).toEqual([]);
    const partial = await scan({ "supabase/a.sql": grant, "supabase/b.sql": "revoke insert on public.notes from anon;" });
    expect(ids(partial)).toEqual(["DB-006"]);
    const other = await scan({ "supabase/a.sql": grant, "supabase/b.sql": "revoke all on public.notes from authenticated;" });
    expect(ids(other)).toEqual(["DB-006"]);
  });

  it("our own revoke fix clears blanket and default-privilege grants", async () => {
    const grants = "grant all on all tables in schema public to anon;\nalter default privileges in schema public grant all on tables to anon;";
    const first = await scan({ "supabase/a.sql": grants });
    expect(ids(first)).toEqual(["DB-006", "DB-006"]);
    const f = await scan({ "supabase/a.sql": grants, "supabase/b.sql": first[0]!.fix.sql! });
    expect(f).toEqual([]);
  });

  it("DB-002 does not count dropped policies", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.t (id int); alter table public.t enable row level security;
        create policy "p" on public.t using (true); drop policy if exists "p" on public.t;`,
    });
    expect(ids(f)).toEqual(["DB-002"]);
  });

  it("DROP FUNCTION and DROP VIEW remove model entries", async () => {
    const f = await scan({
      "supabase/a.sql": `create function public.f() returns void language sql security definer as $$ select 1 $$;
        drop function if exists public.f();
        create view public.v as select 1 as x; drop view public.v;`,
    });
    expect(f).toEqual([]);
  });

  it("DISABLE RLS after enable flags DB-001", async () => {
    const f = await scan({ "supabase/a.sql": "create table public.t (id int); alter table public.t enable row level security; alter table public.t disable row level security;" });
    expect(ids(f)).toEqual(["DB-001"]);
  });
});

describe("bug 2: AS RESTRICTIVE policies", () => {
  it("a restrictive USING (true) is harmless", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.posts (id int, user_id uuid); alter table public.posts enable row level security;
        create policy "own" on public.posts for all to authenticated using ((select auth.uid()) = user_id);
        create policy "r" on public.posts as restrictive for all to anon using (true);`,
    });
    expect(f).toEqual([]);
  });
  it("a permissive USING (true) still fires (control)", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.posts (id int, user_id uuid); alter table public.posts enable row level security;
        create policy "r" on public.posts as permissive for all to anon using (true);`,
    });
    expect(ids(f)).toEqual(["DB-003"]);
  });
});

describe("bug 3: user-data table names are word-bounded", () => {
  const open = (t: string) => ({
    "supabase/a.sql": `create table public.${t} (id int, name text); alter table public.${t} enable row level security;
      create policy "p" on public.${t} for select to anon using (true);`,
  });
  it.each(["catalog", "blog", "denotes", "borders", "dialogue"])("does not treat %s as user data", async (t) => {
    expect(await scan(open(t))).toEqual([]);
  });
  it.each(["user_logs", "orders", "chat_messages", "Notes", "profiles"])("still treats %s as user data", async (t) => {
    expect(ids(await scan(open(t)))).toEqual(["DB-003"]);
  });
});

describe("bug 4: owner columns", () => {
  it("recognises the common owner column names", () => {
    for (const c of ["uid", "owner_uuid", "creator_id", "account_id", "tenant_id", "org_id", "member_id", "author_id", "user_id", "owner"]) {
      expect(ownerColumn(["name", c])).toBe(c);
    }
    expect(ownerColumn(["id", "name"])).toBeUndefined();
    expect(ownerColumn(["id", "name"], { idIsAuthUser: true })).toBe("id");
  });
  it("profiles(id references auth.users) gets DB-004 and an id-based fix", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.profiles (id uuid primary key references auth.users(id), name text, published boolean);
        alter table public.profiles enable row level security;
        create policy "u" on public.profiles for update to authenticated using (published = true);`,
    });
    expect(ids(f)).toEqual(["DB-004"]);
    expect(f[0]!.fix.sql).toContain("auth.uid()) = id");
  });
  it("a plain id column is not an owner column (control)", async () => {
    const f = await scan({
      "supabase/a.sql": `create table public.things (id uuid primary key, published boolean);
        alter table public.things enable row level security;
        create policy "u" on public.things for update to authenticated using (published = true);`,
    });
    expect(ids(f)).toEqual([]);
  });
});

describe("bug 5: RLS state independent of creation order", () => {
  it("ALTER processed before CREATE still enables RLS", async () => {
    const f = await scan({
      "supabase/a.sql": "alter table public.t enable row level security;",
      "supabase/b.sql": "create table public.t (id int);",
    });
    expect(ids(f)).toEqual(["DB-002"]);
  });
  it("ALTER for a dashboard-created table does not crash and is recorded", () => {
    const model = buildModel([{ path: "supabase/a.sql", content: "alter table public.dash enable row level security;" }]);
    expect(model.rls.get("public.dash")).toBe(true);
    expect(model.tables.size).toBe(0);
  });
  it("a dropped and recreated table starts with RLS off (control)", async () => {
    const f = await scan({
      "supabase/a.sql": "create table public.t (id int); alter table public.t enable row level security; drop table public.t; create table public.t (id int);",
    });
    expect(ids(f)).toEqual(["DB-001"]);
  });
});

describe("bug 6: functions are schema and overload aware", () => {
  it("a safe public.f does not hide an unsafe other.f", async () => {
    const f = await scan({
      "supabase/a.sql": `create function public.f() returns void language sql security definer set search_path = '' as $$ select 1 $$;
        create function other.f() returns void language sql security definer as $$ select 1 $$;`,
    });
    expect(f.filter((x) => x.ruleId === "DB-005")).toHaveLength(1);
    expect(f.find((x) => x.ruleId === "DB-005")!.title).toContain("other.f");
  });
  it("overloads are tracked separately", async () => {
    const f = await scan({
      "supabase/a.sql": `create function public.g(a int) returns void language sql security definer set search_path = '' as $$ select 1 $$;
        create function public.g(a int, b int) returns void language sql security definer as $$ select 1 $$;
        revoke execute on function public.g(int, int) from public, anon, authenticated;
        revoke execute on function public.g(int) from public, anon, authenticated;`,
    });
    expect(ids(f)).toEqual(["DB-005"]);
  });
  it("grants on all functions / sequences are not table grants", async () => {
    const f = await scan({
      "supabase/a.sql": "grant all on all functions in schema public to anon; grant all on all sequences in schema public to anon;",
    });
    expect(f).toEqual([]);
  });
  it("grant on all tables still counts (control)", async () => {
    expect(ids(await scan({ "supabase/a.sql": "grant all on all tables in schema public to anon;" }))).toEqual(["DB-006"]);
  });
});

describe("bug 7: expired Firebase test-mode dates", () => {
  const rules = "match /{d=**} {\n allow read, write: if request.time < timestamp.date(2020, 1, 15);\n}";
  const now = new Date("2026-10-05T00:00:00Z");
  it("is still reported, as medium, with the expired wording", () => {
    const f = analyzeFirebaseRules("firestore.rules", rules, ".", now);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.explanation).toContain("expired on 2020-01-15");
    expect(f[0]!.explanation).toContain("closed now");
    expect(f[0]!.explanation).toContain("reopened");
  });
  it("a future date is still critical (control)", () => {
    const f = analyzeFirebaseRules("firestore.rules", rules.replace("2020", "2031"), ".", now);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.explanation).toContain("2031-01-15");
  });
  it("rtdb epoch expiry in the past is medium", () => {
    const f = analyzeFirebaseRules("database.rules.json", '{"rules":{".read":"now < 1600000000000"}}', ".", now);
    expect(f[0]!.severity).toBe("medium");
  });
});
