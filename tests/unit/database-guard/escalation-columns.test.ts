import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { memContext } from "../../helpers/memfs.js";

// Real-corpus regressions for DB-013 (self-escalation), each with a must-still-fire control.
const table = (name: string, cols: string) =>
  `create table public.${name} (id uuid primary key references auth.users, user_id uuid, ${cols});\n` +
  `alter table public.${name} enable row level security;\n` +
  `create policy "own update" on public.${name} for update to authenticated using (auth.uid() = user_id);\n`;

async function db013(sql: string): Promise<string[]> {
  const findings = await agent.run(memContext({ "supabase/migrations/001.sql": sql }));
  return findings.filter((f) => f.ruleId === "DB-013").map((f) => f.title);
}

describe("DB-013 privilege columns", () => {
  it("does not treat a chat message's role (user/assistant) as a privilege", async () => {
    expect(await db013(table("messages", "role text, content text"))).toEqual([]);
    expect(await db013(table("chat_messages", "role text"))).toEqual([]);
  });

  it("still flags role on a profiles table", async () => {
    expect(await db013(table("profiles", "role text, full_name text"))).toHaveLength(1);
  });

  it("does not match privilege words inside longer column names", async () => {
    expect(await db013(table("reports", "admin_notes text, pro_tips text"))).toEqual([]);
  });

  it("still flags exact privilege columns and medium-impact billing columns", async () => {
    const [title] = await db013(table("accounts", "is_admin boolean, credits int"));
    expect(title).toContain("is_admin");
    expect(title).toContain("credits");
  });
});
