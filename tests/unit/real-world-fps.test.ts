import { describe, expect, it } from "vitest";
import { agent as aiGuard } from "../../src/agents/ai-guard/index.js";
import { agent as authAuditor } from "../../src/agents/auth-auditor/index.js";
import { agent as databaseGuard } from "../../src/agents/database-guard/index.js";
import { agent as secretsHunter } from "../../src/agents/secrets-hunter/index.js";
import { agent as webHardener } from "../../src/agents/web-hardener/index.js";
import type { Agent } from "../../src/core/types.js";
import { memContext } from "../helpers/memfs.js";

// Regressions found by scanning popular open-source Next.js/Supabase apps. Each false positive is paired
// with a control that must still be reported, so tuning can never silently weaken real detection.

async function rules(agent: Agent, files: Record<string, string>): Promise<string[]> {
  return (await agent.run(memContext(files))).map((f) => f.ruleId);
}

describe("AuthAuditor: helpers that resolve the caller or check access", () => {
  const body = (auth: string) =>
    `import { db } from "@/lib/db"\nexport async function GET(req: Request) {\n${auth}  const rows = await supabase.from("notes").select("*")\n  return Response.json(rows)\n}\n`;

  it("accepts getServerProfile() as an authentication check (AUTH-002)", async () => {
    expect(await rules(authAuditor, { "app/api/notes/route.ts": body("  const profile = await getServerProfile()\n") })).not.toContain("AUTH-002");
  });

  it("still flags a data route with no check at all (AUTH-002)", async () => {
    expect(await rules(authAuditor, { "app/api/notes/route.ts": body("") })).toContain("AUTH-002");
  });

  const del = (guard: string) =>
    `export async function DELETE(req: Request, context: { params: { postId: string } }) {\n  const { params } = context\n${guard}  await db.post.delete({ where: { id: params.postId } })\n  return new Response(null, { status: 204 })\n}\n`;

  it("accepts verifyCurrentUserHasAccessToPost(id) as the ownership check (AUTH-003)", async () => {
    const guard = "  if (!(await verifyCurrentUserHasAccessToPost(params.postId))) return new Response(null, { status: 403 })\n";
    expect(await rules(authAuditor, { "app/api/posts/[postId]/route.ts": del(guard) })).not.toContain("AUTH-003");
  });

  it("still flags a caller-supplied id used with no ownership check (AUTH-003)", async () => {
    expect(await rules(authAuditor, { "app/api/posts/[postId]/route.ts": del("") })).toContain("AUTH-003");
  });
});

describe("AIGuard: LLM routes behind a session helper", () => {
  const route = (auth: string) =>
    `import OpenAI from "openai"\nexport async function POST(req: Request) {\n${auth}  const { messages } = await req.json()\n  const out = await openai.chat.completions.create({ model: "m", messages, max_tokens: 500 })\n  return Response.json(out)\n}\n`;

  it("accepts getServerProfile() as authentication (AI-004)", async () => {
    expect(await rules(aiGuard, { "app/api/chat/route.ts": route("  const profile = await getServerProfile()\n") })).not.toContain("AI-004");
  });

  it("still flags an open LLM endpoint (AI-004)", async () => {
    expect(await rules(aiGuard, { "app/api/chat/route.ts": route("") })).toContain("AI-004");
  });
});

describe("SecretsHunter: Supabase demo key", () => {
  const jwt = (payload: object) =>
    [Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"), Buffer.from(JSON.stringify(payload)).toString("base64url"), "c2lnbmF0dXJlLXBhZGRpbmctcGFkZGluZw"].join(".");
  const sql = (token: string) => `DECLARE\n  service_role_key TEXT := '${token}';\n`;

  it("ignores the published supabase-demo service_role key", async () => {
    const ids = await rules(secretsHunter, { "supabase/migrations/setup.sql": sql(jwt({ iss: "supabase-demo", role: "service_role", exp: 1983812996 })) });
    expect(ids).not.toContain("SEC-009");
  });

  it("still reports a real project's service_role key", async () => {
    const ids = await rules(secretsHunter, { "supabase/migrations/setup.sql": sql(jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role", exp: 2000000000 })) });
    expect(ids).toContain("SEC-009");
  });
});

describe("WebHardener: HTML sinks fed by constants or escaped React output (WEB-003)", () => {
  it("accepts a constant template literal passed to dangerouslySetInnerHTML", async () => {
    const src = 'const THEME = `(function(){ document.documentElement.dataset.t = "dark"; })();`;\nexport const L = () => <script dangerouslySetInnerHTML={{ __html: THEME }} />;\n';
    expect(await rules(webHardener, { "app/layout.tsx": src })).not.toContain("WEB-003");
  });

  it("accepts innerHTML assigned from renderToString output", async () => {
    const src = 'const html = renderToString(<Message>{content}</Message>);\nconst el = document.createElement("div");\nel.innerHTML = html;\n';
    expect(await rules(webHardener, { "lib/diff.tsx": src })).not.toContain("WEB-003");
  });

  it("still flags a constant that is actually built from user data", async () => {
    const src = "const html = `<b>${req.query.name}</b>`;\nel.innerHTML = html;\n";
    expect(await rules(webHardener, { "lib/x.ts": src })).toContain("WEB-003");
  });

  it("still flags innerHTML from request input and from a variable holding user input", async () => {
    expect(await rules(webHardener, { "lib/a.ts": "el.innerHTML = userInput;\n" })).toContain("WEB-003");
    expect(await rules(webHardener, { "lib/b.ts": "const html = req.body.comment;\nel.innerHTML = html;\n" })).toContain("WEB-003");
  });
});

describe("DatabaseGuard: deliberate sharing policies (DB-004)", () => {
  const table = "create table public.chats (id uuid primary key, user_id uuid, sharing text default 'private');\nalter table public.chats enable row level security;\n";
  const policy = (cmd: string, using: string) => `${table}create policy "p" on public.chats for ${cmd} to authenticated using (${using});\n`;
  const run = (sql: string) => rules(databaseGuard, { "supabase/migrations/001.sql": sql });

  it("does not flag a SELECT policy that filters on the row's own sharing column", async () => {
    expect(await run(policy("select", "sharing <> 'private'"))).not.toContain("DB-004");
  });

  it("still flags a SELECT policy that only checks the caller is signed in", async () => {
    // Now the dedicated DB-017 ("any signed-in user"), which replaces DB-004 for that policy.
    expect(await run(policy("select", "auth.role() = 'authenticated'"))).toContain("DB-017");
  });

  it("still flags a write policy that filters on a non-owner column", async () => {
    expect(await run(policy("update", "sharing <> 'private'"))).toContain("DB-004");
  });

  it("is quiet when the policy uses auth.uid()", async () => {
    expect(await run(policy("select", "auth.uid() = user_id"))).not.toContain("DB-004");
  });
});

describe("WebHardener: constant-only template interpolation (WEB-003)", () => {
  it("accepts ${UPPER_CASE} constants inside a constant template", async () => {
    const src = 'const DARK = "#000";\nconst S = `meta.setAttribute("content", isDark ? "${DARK}" : "#fff");`;\nexport const L = () => <script dangerouslySetInnerHTML={{ __html: S, }} />;\n';
    expect(await rules(webHardener, { "app/layout.tsx": src })).not.toContain("WEB-003");
  });
  it("still flags interpolation of anything that is not a constant", async () => {
    const src = 'const S = `<b>${userName}</b>`;\nexport const L = () => <div dangerouslySetInnerHTML={{ __html: S }} />;\n';
    expect(await rules(webHardener, { "app/layout.tsx": src })).toContain("WEB-003");
  });
});

describe("AIGuard: system prompt injection confidence (AI-002)", () => {
  const route = (system: string) =>
    `export async function POST(req: Request) {\n  const { hints, messages } = await req.json()\n  const out = streamText({ ${system}, messages, maxTokens: 100 })\n  return out\n}\n`;
  const find = async (system: string) => (await aiGuard.run(memContext({ "app/api/chat/route.ts": route(system) }))).find((f) => f.ruleId === "AI-002");

  it("is high confidence when request text goes straight into the system prompt", async () => {
    expect((await find("system: `You are ${hints}`"))?.confidence).toBe("high");
  });
  it("is low confidence when it only reaches a helper function we cannot see into", async () => {
    expect((await find("system: buildSystemPrompt({ hints })"))?.confidence).toBe("low");
  });
});

describe("WebHardener: inline constant scripts and <style> config (WEB-003)", () => {
  it("accepts a long inline constant script even when it contains braces", async () => {
    const src = [
      "export const L = () => (",
      "  <script dangerouslySetInnerHTML={{ __html: `",
      "    setInterval(() => { if (el) { el.textContent = 'x'; } }, 1000);",
      "  ` }} />",
      ");",
    ].join("\n");
    expect(await rules(webHardener, { "app/layout.tsx": src })).not.toContain("WEB-003");
  });

  it("does not treat a literal followed by + user data as constant", async () => {
    const src = 'export const L = () => <div dangerouslySetInnerHTML={{ __html: "<b>" + userName + "</b>" }} />;\n';
    expect(await rules(webHardener, { "app/a.tsx": src })).toContain("WEB-003");
  });

  it("does not treat an inline template with a real interpolation as constant", async () => {
    const src = "export const L = () => <div dangerouslySetInnerHTML={{ __html: `<b>${user.name}</b>` }} />;\n";
    expect(await rules(webHardener, { "app/b.tsx": src })).toContain("WEB-003");
  });

  it("ignores CSS built from a config object inside a <style> element (shadcn chart)", async () => {
    const src = [
      "return (",
      "  <style",
      "    dangerouslySetInnerHTML={{",
      "      __html: Object.entries(THEMES).map(([t, p]) => `${p} [data-chart=${id}] { --c: ${color}; }`).join('\n'),",
      "    }}",
      "  />",
      ");",
    ].join("\n");
    expect(await rules(webHardener, { "components/ui/chart.tsx": src })).not.toContain("WEB-003");
  });

  it("still flags the same expression on a non-style element", async () => {
    const src = "return <div dangerouslySetInnerHTML={{ __html: Object.entries(T).map(([k, v]) => `<i>${v}</i>`).join('') }} />;\n";
    expect(await rules(webHardener, { "components/x.tsx": src })).toContain("WEB-003");
  });
});

describe("WebHardener: unsafe file-upload names reaching a write (WEB-006)", () => {
  it("flags an upload whose file.name is only whitespace-stripped", async () => {
    const src = [
      "export async function PUT(request) {",
      "  const formData = await request.formData();",
      "  const file = formData.get('profile_image');",
      "  const filename = `${user_id}_${Date.now()}_${file.name.replace(/\s/g, '_')}`;",
      "  await writeFile(path.join(uploadDir, filename), buffer);",
      "}",
    ].join("\n");
    expect(await rules(webHardener, { "app/api/upload/route.ts": src })).toContain("WEB-006");
  });

  it("flags req.body/query/params feeding a write with no sanitization", async () => {
    const src = "const name = req.body.filename;\nfs.writeFileSync(path.join(dir, name), data);\n";
    expect(await rules(webHardener, { "server/upload.ts": src })).toContain("WEB-006");
  });

  it("does not flag a server-generated random name", async () => {
    const src = [
      "const file = formData.get('avatar');",
      "const filename = `${randomUUID()}${path.extname(file.name)}`;",
      "await writeFile(path.join(uploadDir, filename), buffer);",
    ].join("\n");
    expect(await rules(webHardener, { "app/api/upload/route.ts": src })).not.toContain("WEB-006");
  });

  it("does not flag a name run through path.basename", async () => {
    const src = [
      "const file = formData.get('avatar');",
      "const filename = path.basename(file.name);",
      "await writeFile(path.join(uploadDir, filename), buffer);",
    ].join("\n");
    expect(await rules(webHardener, { "app/api/upload/route.ts": src })).not.toContain("WEB-006");
  });

  it("does not flag a literal or non-tainted destination", async () => {
    const src = "const out = 'report.pdf';\nfs.writeFileSync(path.join(dir, out), data);\n";
    expect(await rules(webHardener, { "server/report.ts": src })).not.toContain("WEB-006");
  });
});

describe("SecretsHunter: tracked .env that is a template, not a leak (SEC-100)", () => {
  it("does not flag a tracked .env containing only public vars and comments", async () => {
    const env = "# FIXME: configure for your project\nNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_abc\n";
    expect(await rules(secretsHunter, { ".env": env })).not.toContain("SEC-100");
  });

  it("still flags a tracked .env holding a real-looking private value", async () => {
    const env = "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_abc\nDATABASE_URL=postgres://myuser:hunter2hunter2@db.prod.internal/app\n";
    expect(await rules(secretsHunter, { ".env": env })).toContain("SEC-100");
  });

  it("still flags a tracked .env with an empty-named private var holding any non-placeholder value", async () => {
    expect(await rules(secretsHunter, { ".env": "SOME_SECRET=abcdef123456\n" })).toContain("SEC-100");
  });
});

describe("AuthAuditor: caller injected as a wrapper callback parameter (AUTH-002)", () => {
  const action = (sig: string) =>
    `export const updatePassword = validatedActionWithUser(\n  schema,\n  ${sig} => {\n    db.update(users).set({ x: 1 }).where(eq(users.id, user.id));\n  }\n);\n`;

  it("accepts a trailing user/session/currentUser parameter as an auth check", async () => {
    expect(await rules(authAuditor, { "app/actions.ts": action("async (data, formData, user)") })).not.toContain("AUTH-002");
    expect(await rules(authAuditor, { "app/actions.ts": action("async (data, formData, session)") })).not.toContain("AUTH-002");
  });

  it("still flags a plain handler with no injected caller at all", async () => {
    const src = "export async function POST(req) {\n  const body = await req.json();\n  db.update(users).set(body);\n}\n";
    expect(await rules(authAuditor, { "app/api/x/route.ts": src })).toContain("AUTH-002");
  });
});

describe("SecretsHunter: a local-only DB URL in a tracked .env is not a leak", () => {
  it("does not flag a Postgres/PGLite default local connection string", async () => {
    const env = "NEXT_PUBLIC_X=y\nDATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres\n";
    expect(await rules(secretsHunter, { ".env": env })).not.toContain("SEC-100");
  });

  it("still flags a connection string pointing at a real host", async () => {
    const env = "DATABASE_URL=postgresql://postgres:postgres@db.myproject.internal:5432/postgres\n";
    expect(await rules(secretsHunter, { ".env": env })).toContain("SEC-100");
  });
});

describe("SecretsHunter: a boolean/numeric flag is not a secret (SEC-100)", () => {
  it("does not flag a tracked .env with only a local DB URL and trivial flags", async () => {
    const env = "NEXT_TELEMETRY_DISABLED=1\nDEBUG=false\nDATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres\n";
    expect(await rules(secretsHunter, { ".env": env })).not.toContain("SEC-100");
  });
});
