import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/ai-guard/index.js";
import { memContext } from "../../helpers/memfs.js";
import { only, scan } from "./helpers.js";

// Built at runtime so no token-shaped literal is committed.
const FAKE_KEY = ["sk", "abcdefghijklmnopqrstuvwxyz123456"].join("-");
const BAD = `"use client";\nimport OpenAI from "openai";\nconst c = new OpenAI({ apiKey: "${FAKE_KEY}" });\n`;

describe("agent", () => {
  it("declares id and static mode", () => {
    expect(agent.id).toBe("ai-guard");
    expect(agent.modes).toEqual(["static"]);
  });

  it("builds complete findings and registers literal keys", async () => {
    const ctx = memContext({ "app/c.tsx": BAD });
    const [f] = await agent.run(ctx);
    expect(f).toBeDefined();
    expect(f?.agentId).toBe("ai-guard");
    expect(f?.explanation.length).toBeGreaterThan(80);
    expect(f?.fix.agentPrompt).toContain("app/c.tsx");
    expect(f?.fix.agentPrompt).toContain("line 3");
    expect(f?.fix.patch?.file).toBe("app/c.tsx");
    expect(f?.fix.references.length).toBeGreaterThan(0);
    expect(f?.evidence[0]?.snippet.length).toBeLessThanOrEqual(200);
    expect(f?.verify.ruleId).toBe("AI-001");
    expect(ctx.secrets.has(FAKE_KEY)).toBe(true);
  });

  it("truncates long evidence lines", async () => {
    const long = "x".repeat(400);
    const f = await scan({ "app/c.tsx": `"use client";\nimport OpenAI from "openai";\nconst c = new OpenAI({ apiKey: k, dangerouslyAllowBrowser: true, p: "${long}" });\n` });
    expect(only(f, "AI-001")[0]?.evidence[0]?.snippet.length).toBeLessThanOrEqual(200);
  });

  it("skips non-code, tests, vendored, declaration, ignored and oversized files", async () => {
    const f = await scan({
      "README.md": BAD,
      "app/c.test.tsx": BAD,
      "node_modules/x/index.js": BAD,
      "dist/a.js": BAD,
      "types/x.d.ts": BAD,
      "app/big.tsx": BAD + "//" + "y".repeat(400_000),
    });
    expect(f).toEqual([]);
  });

  it("handles unreadable files and scans .mjs/.jsx/.js", async () => {
    const ctx = memContext({ "a/b.mjs": BAD, "c/d.jsx": BAD, "e/f.js": BAD });
    const ctx2 = { ...ctx, files: { ...ctx.files, paths: [...ctx.files.paths, "ghost.ts"] } };
    expect((await agent.run(ctx2)).length).toBe(3);
  });

  it("sorts deterministically", async () => {
    const a = await scan({ "b.tsx": BAD, "a.tsx": BAD });
    expect(a.map((x) => x.evidence[0]?.file)).toEqual(["a.tsx", "b.tsx"]);
  });
});

