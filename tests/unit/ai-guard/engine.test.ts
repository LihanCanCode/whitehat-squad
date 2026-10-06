import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/ai-guard/index.js";
import { memContext } from "../../helpers/memfs.js";
import { only, rules, scan } from "./helpers.js";

const HEAD = `import OpenAI from "openai";\nconst openai = new OpenAI();\n`;

describe("per-unit guards (AI-004 / AI-005)", () => {
  it("does not let a sibling GET that calls getUser hide an unauthenticated POST", async () => {
    const src =
      HEAD +
      `export async function GET() {\n  const { data } = await supabase.auth.getUser();\n  return Response.json(data);\n}\n` +
      `export async function POST(req: Request) {\n  const { message } = await req.json();\n  const r = await openai.chat.completions.create({ model: "m", max_tokens: 5, messages: [{ role: "user", content: message }] });\n  return Response.json(r);\n}\n`;
    const hit = only(await scan({ "app/api/chat/route.ts": src }), "AI-004");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.evidence[0]?.line).toBe(9);
  });

  it("control: the same POST is quiet once it checks the user itself", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { data } = await supabase.auth.getUser();\n  const { message } = await req.json();\n  const r = await openai.chat.completions.create({ model: "m", max_tokens: 5, messages: [{ role: "user", content: message }] });\n  return Response.json(r);\n}\n`;
    expect(rules(await scan({ "app/api/chat/route.ts": src }))).not.toContain("AI-004");
  });

  it("does not count the words 'Rate-limit exceeded' in a string as rate limiting", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { message } = await req.json();\n  const r = await openai.chat.completions.create({ model: "m", max_tokens: 5, messages: [{ role: "user", content: message }] });\n  if (!r) return new Response("Rate-limit exceeded", { status: 429 });\n  return Response.json(r);\n}\n`;
    expect(rules(await scan({ "app/api/chat/route.ts": src }))).toContain("AI-004");
  });

  it("control: a real limiter call still counts", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { success } = await ratelimit.limit("ip");\n  const { message } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: "m", max_tokens: 5, messages: [{ role: "user", content: message }] }));\n}\n`;
    expect(rules(await scan({ "app/api/chat/route.ts": src }))).not.toContain("AI-004");
  });

  it("checks the input cap and max_tokens per call, not once per file", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { message } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: message }] }));\n}\n` +
      `export async function PUT(req: Request) {\n  const { message } = await req.json();\n  const text = message.slice(0, 500);\n  return Response.json(await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: text }] }));\n}\n`;
    const hits = only(await scan({ "app/api/chat/route.ts": src }), "AI-005");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence[0]?.line).toBe(5);
  });

  it("does not let max_tokens on one call excuse a second call", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { message } = await req.json();\n  await openai.chat.completions.create({ model: "m", max_tokens: 10, messages: [] });\n  return Response.json(await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: message }] }));\n}\n`;
    expect(only(await scan({ "app/api/chat/route.ts": src }), "AI-005")).toHaveLength(1);
  });

  it("applies the guard to Express handlers registered separately", async () => {
    const src =
      `const express = require("express");\nconst OpenAI = require("openai");\nconst o = new OpenAI();\nconst app = express();\n` +
      `app.get("/me", requireAuth, (req, res) => res.json({}));\n` +
      `app.post("/chat", async (req, res) => {\n  const r = await o.chat.completions.create({ model: "m", max_tokens: 5, messages: [{ role: "user", content: req.body.q }] });\n  res.json(r);\n});\n`;
    const hit = only(await scan({ "server.js": src }), "AI-004");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.evidence[0]?.line).toBe(7);
  });
});

describe("per-unit taint (AI-002)", () => {
  it("does not leak taint from one handler into another", async () => {
    const src =
      HEAD +
      `export async function POST(req: Request) {\n  const { persona } = await req.json();\n  return Response.json({ persona });\n}\n` +
      `export async function GET() {\n  const persona = "pirate";\n  return openai.chat.completions.create({ model: "m", max_tokens: 5, system: \`You are \${persona}\` });\n}\n`;
    expect(rules(await scan({ "app/api/chat/route.ts": src }))).not.toContain("AI-002");
  });

  it("control: the handler that does read the body is still flagged", async () => {
    const src = HEAD + `export async function POST(req: Request) {\n  const { persona } = await req.json();\n  return openai.chat.completions.create({ model: "m", max_tokens: 5, system: \`You are \${persona}\` });\n}\n`;
    expect(rules(await scan({ "app/api/chat/route.ts": src }))).toContain("AI-002");
  });
});

describe("AI-003 output seeds", () => {
  const route = (body: string): Record<string, string> => ({
    "app/api/c/route.ts": `import OpenAI from "openai";\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { messages } = await req.json();\n${body}\n}\n`,
  });

  it("does not treat the user's own chat messages as model output", async () => {
    const f = await scan(route("  const history = messages.map((m) => m.content).join(' ');\n  await db.query(history);\n  for (const message of messages) { await db.query(message.content); }"));
    expect(rules(f)).not.toContain("AI-003");
  });

  it("does not treat the request's message.content as model output", async () => {
    const f = await scan(route("  const message = messages[0];\n  el.innerHTML = message.content;"));
    expect(rules(f)).not.toContain("AI-003");
  });

  it("control: an actual completion's content still reaches the sink", async () => {
    const f = await scan(route("  const completion = await openai.chat.completions.create({ model: 'm', max_tokens: 5, messages });\n  const message = completion.choices[0].message;\n  el.innerHTML = message.content;"));
    expect(rules(f)).toContain("AI-003");
  });

  it("does not read String.raw as a SQL .raw( sink", async () => {
    const f = await scan({
      "lib/x.ts": `import { generateText } from "ai";\nexport async function f() {\n  const { text } = await generateText({ model, prompt: "x", maxTokens: 5 });\n  return String.raw(text);\n}\n`,
    });
    expect(rules(f)).not.toContain("AI-003");
  });

  it("control: knex.raw with model output is still SQL injection", async () => {
    const f = await scan({
      "lib/x.ts": `import { generateText } from "ai";\nexport async function f() {\n  const { text } = await generateText({ model, prompt: "x", maxTokens: 5 });\n  return knex.raw(text);\n}\n`,
    });
    expect(rules(f)).toContain("AI-003");
  });
});

describe("AI-007 across files", () => {
  it("flags a public-prefixed model key in .env files", async () => {
    const f = await scan({ ".env.local": "# comment\nNEXT_PUBLIC_OPENAI_API_KEY=abc123realvalue\nOTHER=1\n" });
    const hit = only(f, "AI-007");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.evidence[0]).toMatchObject({ file: ".env.local", line: 2 });
    expect(hit[0]?.severity).toBe("critical");
  });

  it("treats a template env file as lower severity and ignores comments and unrelated vars", async () => {
    const f = await scan({ ".env.example": "# NEXT_PUBLIC_OPENAI_API_KEY=\nNEXT_PUBLIC_ANTHROPIC_API_KEY=\nNEXT_PUBLIC_SUPABASE_URL=x\n" });
    const hit = only(f, "AI-007");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("medium");
  });

  it("ignores a key name that only appears in a string or a comment in code", async () => {
    const src = `"use client";\n// process.env.NEXT_PUBLIC_OPENAI_API_KEY\nconst hint = "set NEXT_PUBLIC_OPENAI_API_KEY to use this";\nconst t = \`rename NEXT_PUBLIC_GROQ_API_KEY\`;\n`;
    expect(rules(await scan({ "app/x.tsx": src }))).not.toContain("AI-007");
  });

  it("control: bracket access with a string key is still a real read", async () => {
    const src = `"use client";\nconst k = process.env["NEXT_PUBLIC_OPENAI_API_KEY"];\n`;
    expect(rules(await scan({ "app/x.tsx": src }))).toContain("AI-007");
  });

  it("does not do its own whsquad-ignore handling (central suppression owns it)", async () => {
    const src = `"use client";\n// whsquad-ignore AI-007\nconst k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n`;
    expect(rules(await scan({ "app/x.tsx": src }))).toContain("AI-007");
  });
});

describe("file filtering", () => {
  // .gitignore cannot hide committed code (security review); test paths are still skipped.
  it("skips test-path files but not gitignored source", async () => {
    const bad = `"use client";\nconst k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n`;
    const ctx = memContext({ ".gitignore": "gen/\n", "gen/a.tsx": bad, "e2e/b.tsx": bad, "app/c.tsx": bad });
    const f = await agent.run(ctx);
    expect(f.map((x) => x.evidence[0]?.file).sort()).toEqual(["app/c.tsx", "gen/a.tsx"]);
  });
});

describe("AI-008 MCP tool handlers", () => {
  const mcp = (handler: string, extra = ""): Record<string, string> => ({
    "src/server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nimport { z } from "zod";\nimport { exec } from "node:child_process";\nimport fs from "node:fs/promises";\nconst server = new McpServer({ name: "x", version: "1" });\n${extra}${handler}\n`,
  });

  it("flags exec of a tool argument as critical", async () => {
    const f = await scan(mcp(`server.tool("run", { cmd: z.string() }, async ({ cmd }) => {\n  const out = exec(\`sh -c \${cmd}\`);\n  return { content: [] };\n});`));
    const hit = only(f, "AI-008");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("critical");
    expect(hit[0]?.cwe).toBe("CWE-78");
    expect(hit[0]?.evidence[0]?.line).toBe(7);
  });

  it("flags fetch, readFile and SQL query as high", async () => {
    const f = await scan(
      mcp(
        `server.registerTool("get", { inputSchema: { url: z.string() } }, async (args) => {\n  const r = await fetch(args.url);\n  return { content: [] };\n});\n` +
          `server.tool("read", { p: z.string() }, async ({ p }) => {\n  const t = await fs.readFile(p, "utf8");\n  return { content: [] };\n});\n` +
          `server.tool("q", { sql: z.string() }, async ({ sql }) => {\n  await db.query(sql);\n  return { content: [] };\n});`,
      ),
    );
    const hits = only(f, "AI-008");
    expect(hits).toHaveLength(3);
    expect(hits.every((h) => h.severity === "high")).toBe(true);
    expect(hits.map((h) => h.cwe).sort()).toEqual(["CWE-22", "CWE-89", "CWE-918"]);
  });

  it("flags the low-level setRequestHandler(CallToolRequestSchema ...) form", async () => {
    const f = await scan(
      mcp(`server.setRequestHandler(CallToolRequestSchema, async (request) => {\n  const { name, arguments: args } = request.params;\n  await fs.writeFile(args.path, args.body);\n  return { content: [] };\n});`),
    );
    expect(rules(f)).toContain("AI-008");
  });

  it("is quiet when the handler checks an allowlist", async () => {
    const f = await scan(
      mcp(`const ALLOWED = new Set(["https://api.example.com"]);\nserver.tool("get", { url: z.string() }, async ({ url }) => {\n  if (!ALLOWED.has(new URL(url).origin)) throw new Error("no");\n  const r = await fetch(url);\n  return { content: [] };\n});`),
    );
    expect(rules(f)).not.toContain("AI-008");
  });

  it("is quiet for constant sinks and for non-MCP files", async () => {
    const constant = await scan(mcp(`server.tool("ls", {}, async () => {\n  const t = await fs.readFile("/etc/motd", "utf8");\n  return { content: [] };\n});`));
    const other = await scan({ "lib/a.ts": `export const x = (server: any) => server.tool("run", {}, async ({ cmd }) => { exec(cmd); });\n` });
    expect(rules(constant)).not.toContain("AI-008");
    expect(rules(other)).not.toContain("AI-008");
  });
});

describe("AI-009 vector search without a tenant filter", () => {
  const authed = (body: string): Record<string, string> => ({
    "package.json": JSON.stringify({ dependencies: { "@clerk/nextjs": "5" } }),
    "app/api/search/route.ts": `import { Pinecone } from "@pinecone-database/pinecone";\nconst index = new Pinecone().index("docs");\nexport async function POST(req: Request) {\n  const { userId } = await auth();\n  const { vector } = await req.json();\n${body}\n}\n`,
  });

  it("flags a Pinecone query with no filter or namespace (medium, low confidence)", async () => {
    const hit = only(await scan(authed("  const r = await index.query({ vector, topK: 5 });")), "AI-009");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("medium");
    expect(hit[0]?.confidence).toBe("low");
  });

  it("flags a Supabase match_documents RPC without a user argument", async () => {
    const f = await scan(authed("  const r = await supabase.rpc('match_documents', { query_embedding: vector, match_count: 5 });"));
    expect(rules(f)).toContain("AI-009");
  });

  it("flags pgvector SQL with no user predicate", async () => {
    const f = await scan(authed("  const r = await sql`SELECT id, content FROM docs ORDER BY embedding <=> ${vector} LIMIT 5`;"));
    expect(rules(f)).toContain("AI-009");
  });

  it("is quiet with a namespace, filter, user argument or user predicate", async () => {
    expect(rules(await scan(authed("  const r = await index.namespace(userId).query({ vector, topK: 5 });")))).not.toContain("AI-009");
    expect(rules(await scan(authed("  const r = await index.query({ vector, topK: 5, filter: { user_id: userId } });")))).not.toContain("AI-009");
    expect(rules(await scan(authed("  const r = await supabase.rpc('match_documents', { query_embedding: vector, user_id: userId });")))).not.toContain("AI-009");
    expect(rules(await scan(authed("  const r = await sql`SELECT id FROM docs WHERE user_id = ${userId} ORDER BY embedding <=> ${vector} LIMIT 5`;")))).not.toContain("AI-009");
  });

  it("is quiet in an app without per-user auth", async () => {
    const f = await scan({ "lib/rag.ts": `const index = pc.index("docs");\nexport const find = (vector: number[]) => index.query({ vector, topK: 5 });\n` });
    expect(rules(f)).not.toContain("AI-009");
  });
});

describe("AI-010 agent loops without a step cap", () => {
  it("flags maxSteps above 20 and stepCountIs above 20", async () => {
    const a = await scan({ "lib/a.ts": `import { generateText } from "ai";\nexport const run = () => generateText({ model, tools, maxSteps: 50, prompt: "x", maxTokens: 5 });\n` });
    const b = await scan({ "lib/b.ts": `import { streamText, stepCountIs } from "ai";\nexport const run = () => streamText({ model, tools, stopWhen: stepCountIs(100), prompt: "x", maxTokens: 5 });\n` });
    expect(only(a, "AI-010")[0]?.severity).toBe("low");
    expect(rules(b)).toContain("AI-010");
  });

  it("flags a tool-enabled call inside while(true) with no counter", async () => {
    const src = `import OpenAI from "openai";\nconst o = new OpenAI();\nexport async function agent(messages: any[]) {\n  while (true) {\n    const r = await o.chat.completions.create({ model: "m", max_tokens: 5, tools, messages });\n    if (!r.choices[0].message.tool_calls) return r;\n  }\n}\n`;
    const hit = only(await scan({ "lib/agent.ts": src }), "AI-010");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.evidence[0]?.line).toBe(5);
  });

  it("flags a recursive tool-enabled call", async () => {
    const src = `import { generateText } from "ai";\nexport async function loop(messages: any[]): Promise<any> {\n  const r = await generateText({ model, tools, messages, maxTokens: 5 });\n  return r.toolCalls.length ? loop(messages) : r;\n}\n`;
    expect(rules(await scan({ "lib/agent.ts": src }))).toContain("AI-010");
  });

  it("is quiet with a small cap, an iteration counter, or no loop", async () => {
    const capped = await scan({ "lib/a.ts": `import { generateText, stepCountIs } from "ai";\nexport const run = () => generateText({ model, tools, stopWhen: stepCountIs(5), prompt: "x", maxTokens: 5 });\n` });
    const counted = await scan({
      "lib/b.ts": `import OpenAI from "openai";\nconst o = new OpenAI();\nexport async function agent(m: any[]) {\n  let steps = 0;\n  while (true) {\n    if (steps++ > 8) break;\n    await o.chat.completions.create({ model: "m", max_tokens: 5, tools, messages: m });\n  }\n}\n`,
    });
    const single = await scan({ "lib/c.ts": `import { generateText } from "ai";\nexport const run = () => generateText({ model, tools, prompt: "x", maxTokens: 5 });\n` });
    expect(rules(capped)).not.toContain("AI-010");
    expect(rules(counted)).not.toContain("AI-010");
    expect(rules(single)).not.toContain("AI-010");
  });
});

describe("AI-005 through a local helper called by a controller", () => {
  const ctl = (cap: string): Record<string, string> => ({
    "controllers/plan.ts": `import { GoogleGenerativeAI } from "@google/generative-ai";\nconst genAI = new GoogleGenerativeAI("k");\nconst gen = async (prompt: string) => {\n  const m = genAI.getGenerativeModel({ model: "x" });\n  return m.generateContent(prompt);\n};\nexport const plan = async (req: any, res: any) => {\n${cap}  const { to } = req.body;\n  res.json(await gen(\`Plan a trip to \${to}\`));\n};\n`,
  });
  it("flags the helper's model call when the controller feeds it request data", async () => {
    expect(rules(await scan(ctl("")))).toContain("AI-005");
  });
  it("control: quiet when the controller caps the input", async () => {
    expect(rules(await scan(ctl("  if (String(req.body.to).length > 80) return;\n")))).not.toContain("AI-005");
  });
});
