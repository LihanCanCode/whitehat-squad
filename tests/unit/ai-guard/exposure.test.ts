import { describe, expect, it } from "vitest";
import { only, rules, scan } from "./helpers.js";

const VITE = { frameworks: ["vite" as const], backends: [], routes: [] };

describe("AI-001 LLM SDK in client code", () => {
  it("flags an SDK client constructed in a 'use client' file", async () => {
    const f = await scan({
      "app/chat.tsx": `"use client";\nimport OpenAI from "openai";\nconst c = new OpenAI({ apiKey: process.env.KEY });\nexport default function Chat() { return null }\n`,
    });
    const hit = only(f, "AI-001");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("critical");
    expect(hit[0]?.evidence[0]?.line).toBe(3);
    expect(hit[0]?.cwe).toBe("CWE-798");
  });

  it("flags dangerouslyAllowBrowser: true even in a non-client path", async () => {
    const f = await scan({
      "lib/ai.ts": `import OpenAI from "openai";\nexport const c = new OpenAI({ apiKey: k, dangerouslyAllowBrowser: true });\n`,
    });
    expect(only(f, "AI-001")[0]?.evidence[0]?.line).toBe(2);
  });

  it("flags Anthropic SDK in a Vite src tree", async () => {
    const f = await scan(
      {
        "vite.config.ts": "export default {}",
        "src/api.ts": `import Anthropic from "@anthropic-ai/sdk";\nconst a = new Anthropic({ apiKey: import.meta.env.X });\n`,
      },
      VITE,
    );
    expect(rules(f)).toContain("AI-001");
  });

  it("flags a browser fetch to api.openai.com with an Authorization header", async () => {
    const f = await scan({
      "app/c.tsx": `'use client'\nasync function go() {\n  await fetch("https://api.openai.com/v1/chat/completions", { headers: { Authorization: "Bearer " + k } });\n}\n`,
    });
    expect(only(f, "AI-001")[0]?.evidence[0]?.line).toBe(3);
  });

  it("does not flag a client component that calls its own /api route", async () => {
    const f = await scan({ "app/c.tsx": `"use client";\nexport async function go() { await fetch("/api/chat", { method: "POST" }); }\n` });
    expect(rules(f)).not.toContain("AI-001");
  });

  it("does not flag a server route or a Next src file without 'use client'", async () => {
    const f = await scan(
      {
        "app/api/chat/route.ts": `import OpenAI from "openai";\nconst c = new OpenAI({ apiKey: process.env.K });\n`,
        "src/lib/llm.ts": `import OpenAI from "openai";\nexport const c = new OpenAI({ apiKey: process.env.K });\n`,
      },
      { frameworks: ["next"], backends: [], routes: [] },
    );
    expect(rules(f)).not.toContain("AI-001");
  });

  it("ignores type-only imports in client files", async () => {
    const f = await scan({ "app/c.tsx": `"use client";\nimport type OpenAI from "openai";\nexport type T = OpenAI.Chat.ChatCompletion;\n` });
    expect(rules(f)).not.toContain("AI-001");
  });

});

describe("AI-007 model key in client bundle", () => {
  it("flags VITE_OPENAI_API_KEY in a Vite client file", async () => {
    const f = await scan({ "vite.config.ts": "", "src/ai.ts": `const key = import.meta.env.VITE_OPENAI_API_KEY;\n` }, VITE);
    const hit = only(f, "AI-007");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("critical");
    expect(hit[0]?.cwe).toBe("CWE-798");
  });

  it("flags NEXT_PUBLIC_ANTHROPIC key in a 'use client' file", async () => {
    const f = await scan({ "app/x.tsx": `"use client";\nconst k = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY;\n` });
    expect(rules(f)).toContain("AI-007");
  });

  it("downgrades when seen outside a client file", async () => {
    const f = await scan({ "app/api/x/route.ts": `const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n` });
    const hit = only(f, "AI-007")[0];
    expect(hit?.severity).toBe("high");
    expect(hit?.confidence).toBe("medium");
  });

  it("ignores unrelated public vars and commented-out code", async () => {
    const f = await scan({
      "app/x.tsx": `"use client";\nconst u = process.env.NEXT_PUBLIC_SUPABASE_URL;\n// const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n`,
    });
    expect(rules(f)).not.toContain("AI-007");
  });

});
