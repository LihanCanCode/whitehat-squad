import { describe, expect, it } from "vitest";
import { CLEAN_ROUTE, only, rules, scan } from "./helpers.js";

const call = (inner: string, pre = ""): string =>
  `import OpenAI from "openai";\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n${pre}  const { message } = await req.json();\n  const r = await openai.chat.completions.create({ model: "m", max_tokens: 10, messages: [{ role: "user", content: message }] });\n${inner}\n  return Response.json({});\n}\n`;

describe("AI-004 unauthenticated, unthrottled LLM route", () => {
  it("flags a route with no auth and no rate limit", async () => {
    const f = await scan({ "app/api/chat/route.ts": call("") });
    const hit = only(f, "AI-004");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("high");
    expect(hit[0]?.cwe).toBe("CWE-306");
    expect(hit[0]?.evidence[0]?.line).toBe(5);
  });

  it("flags a server action", async () => {
    const f = await scan({ "app/actions.ts": `"use server";\nimport { generateText } from "ai";\nexport async function ask(q: string) {\n  return generateText({ model, prompt: q, maxTokens: 10 });\n}\n` });
    expect(rules(f)).toContain("AI-004");
  });

  it("is quiet when auth or a rate limiter is present", async () => {
    const auth = await scan({ "app/api/chat/route.ts": call("", "  const session = await getServerSession();\n  if (!session) return new Response('no', { status: 401 });\n") });
    const rl = await scan({ "app/api/chat/route.ts": call("", "  const { success } = await ratelimit.limit(ip);\n") });
    expect(rules(auth)).not.toContain("AI-004");
    expect(rules(rl)).not.toContain("AI-004");
  });

  it("lowers confidence when middleware exists with auth", async () => {
    const f = await scan({
      "app/api/chat/route.ts": call(""),
      "middleware.ts": `import { auth } from "@clerk/nextjs/server";\nexport default auth;\n`,
    });
    expect(only(f, "AI-004")[0]?.confidence).toBe("low");
  });

  it("ignores helper libraries that are not routes and unrelated messages.create", async () => {
    const lib = await scan({ "lib/llm.ts": `import OpenAI from "openai";\nconst o = new OpenAI();\nexport const ask = (m: string) => o.chat.completions.create({ model: "m", max_tokens: 5, messages: [] });\n` });
    const twilio = await scan({ "app/api/sms/route.ts": `import twilio from "twilio";\nexport async function POST() { await client.messages.create({ body: "x" }); }\n` });
    expect(rules(lib)).not.toContain("AI-004");
    expect(rules(twilio)).toEqual([]);
  });

});

describe("AI-005 cost DoS", () => {
  const route = (args: string, pre = ""): Record<string, string> => ({
    "app/api/c/route.ts": `import OpenAI from "openai";\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { message } = await req.json();\n${pre}  await openai.chat.completions.create({ ${args} });\n}\n`,
  });

  it("flags missing max_tokens with uncapped user text", async () => {
    const f = await scan(route('model: "m", messages: [{ role: "user", content: message }]'));
    const hit = only(f, "AI-005");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("medium");
    expect(hit[0]?.cwe).toBe("CWE-770");
  });

  it("is quiet with max_tokens, max_completion_tokens, or an input cap", async () => {
    expect(rules(await scan(route('model: "m", max_tokens: 100, messages: []')))).not.toContain("AI-005");
    expect(rules(await scan(route('model: "m", max_completion_tokens: 100')))).not.toContain("AI-005");
    expect(rules(await scan(route('model: "m", messages: [{ content: message }]', "  if (message.length > 2000) return;\n")))).not.toContain("AI-005");
    expect(rules(await scan(route('model: "m", messages: [{ content: message.slice(0, 500) }]')))).not.toContain("AI-005");
  });

  it("is quiet when the call takes a pre-built params object that sets a cap", async () => {
    const f = await scan({
      "app/api/c/route.ts": `import OpenAI from "openai";\nconst openai = new OpenAI();\nconst params = { model: "m", max_tokens: 5 };\nexport async function POST(req: Request) {\n  const { m } = await req.json();\n  await openai.chat.completions.create(params);\n}\n`,
    });
    expect(rules(f)).not.toContain("AI-005");
  });

  it("is quiet when no user input is involved", async () => {
    const f = await scan({ "scripts/gen.ts": `import OpenAI from "openai";\nconst o = new OpenAI();\nawait o.chat.completions.create({ model: "m", messages: [] });\n` });
    expect(rules(f)).not.toContain("AI-005");
  });

});

describe("baseline", () => {
  it("reports nothing for a hardened route", async () => {
    expect(await scan({ "app/api/chat/route.ts": CLEAN_ROUTE })).toEqual([]);
  });
});
