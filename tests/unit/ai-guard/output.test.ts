import { describe, expect, it } from "vitest";
import { only, rules, scan } from "./helpers.js";

const wrap = (body: string, imports = ""): Record<string, string> => ({
  "app/api/run/route.ts": `import OpenAI from "openai";\n${imports}const openai = new OpenAI();\nexport async function POST() {\n  const completion = await openai.chat.completions.create({ max_tokens: 5, model: "m" });\n  const out = completion.choices[0].message.content;\n${body}\n}\n`,
});

describe("AI-003 insecure handling of LLM output", () => {
  it("flags eval on a tainted variable as critical", async () => {
    const f = await scan(wrap("  eval(out);"));
    const hit = only(f, "AI-003");
    expect(hit).toHaveLength(1);
    expect(hit[0]?.severity).toBe("critical");
    expect(hit[0]?.cwe).toBe("CWE-94");
  });

  it("flags inline output expression and new Function", async () => {
    expect(rules(await scan(wrap("  eval(completion.choices[0].message.content);")))).toContain("AI-003");
    expect(rules(await scan(wrap("  const fn = new Function(out);")))).toContain("AI-003");
  });

  it("flags child_process exec with interpolated output", async () => {
    const f = await scan(wrap("  exec(`ls ${out}`);", 'import { exec } from "child_process";\n'));
    expect(only(f, "AI-003")[0]?.severity).toBe("critical");
  });

  it("flags raw SQL built from output but not parameterised values", async () => {
    expect(rules(await scan(wrap("  await db.query(`SELECT * FROM t WHERE n = '${out}'`);")))).toContain("AI-003");
    expect(rules(await scan(wrap("  await db.query(out);")))).toContain("AI-003");
    expect(rules(await scan(wrap('  await db.query("SELECT * FROM t WHERE n = $1", [out]);')))).not.toContain("AI-003");
  });

  it("flags dangerouslySetInnerHTML, innerHTML and dynamic import", async () => {
    expect(rules(await scan(wrap("  return <div dangerouslySetInnerHTML={{ __html: out }} />;")))).toContain("AI-003");
    expect(rules(await scan(wrap("  el.innerHTML = out;")))).toContain("AI-003");
    const imp = await scan(wrap("  await import(out);"));
    expect(only(imp, "AI-003")[0]?.severity).toBe("high");
  });

  it("flags tool dispatch by model-supplied name without an allowlist", async () => {
    const f = await scan({
      "lib/t.ts": `import OpenAI from "openai";\nexport async function go(c: any) {\n  const call = c.choices[0].message.tool_calls[0];\n  const name = call.function.name;\n  return handlers[name](call.function.arguments);\n}\n`,
    });
    expect(rules(f)).toContain("AI-003");
  });

  it("does not flag tool dispatch guarded by an allowlist", async () => {
    const guarded = await scan({
      "lib/t.ts": `import OpenAI from "openai";\nconst ALLOWED = ["a"];\nexport async function go(toolCall: any) {\n  const name = toolCall.function.name;\n  if (!ALLOWED.includes(name)) throw new Error("no");\n  return handlers[name]();\n}\n`,
    });
    expect(rules(guarded)).not.toContain("AI-003");
  });

  it("flags text from generateText", async () => {
    const f = await scan({
      "lib/g.ts": `import { generateText } from "ai";\nexport async function g() {\n  const { text } = await generateText({ model, prompt, maxTokens: 10 });\n  const r = await generateText({ model, prompt, maxTokens: 10 });\n  eval(text);\n  eval(r.text);\n}\n`,
    });
    expect(only(f, "AI-003")).toHaveLength(2);
  });

  it("does not flag safe uses of output", async () => {
    const f = await scan(wrap("  const data = JSON.parse(out);\n  /abc/.exec(out);\n  return Response.json({ out });"));
    expect(rules(f)).not.toContain("AI-003");
  });

  it("does not flag files that do not use an LLM", async () => {
    const f = await scan({ "lib/x.ts": `export function f(response: any) { eval(response.content); }\n` });
    expect(rules(f)).not.toContain("AI-003");
  });

});
