import { describe, expect, it } from "vitest";
import { runScan } from "../../src/core/orchestrator.js";
import { SQUAD } from "../../src/core/registry.js";
import { memFiles } from "../helpers/memfs.js";

// Security review: a hostile repo must not hang the scan (CI minutes burned, nothing reported).
// Quadratic regexes take minutes on these inputs; linear ones take well under a second.
const SIZE = 300_000;
const LIMIT_MS = 5_000;

const CASES: Record<string, Record<string, string>> = {
  "blank lines in a .py file": { "app.py": "import os\n" + "\n".repeat(SIZE) + "x = 1\n" },
  "blank lines in an .env file": { ".env": "A=1\n" + "\n".repeat(SIZE) + "B=2\n" },
  "blank lines in a migration": { "supabase/migrations/1.sql": "\n".repeat(SIZE) + "create table public.t (id int);\n" },
  "blank lines in a route": { "app/api/x/route.ts": "export async function POST(req: Request) {\n" + "\n".repeat(SIZE) + "}\n" },
  "a line of open braces": { "app/api/x/route.ts": `const a = ${"{".repeat(SIZE)}\n` },
  "deeply nested brackets": { "src/x.ts": `${"([".repeat(SIZE / 4)}x\n` },
  "whitespace runs before =": { ".env.local": `JWT_SECRET${" ".repeat(SIZE)}\n` },
};

describe("hostile input does not hang the squad", () => {
  for (const [name, files] of Object.entries(CASES)) {
    it(name, async () => {
      const started = Date.now();
      await runScan({ mode: "static", targetLabel: ".", files: memFiles(files), agents: SQUAD });
      expect(Date.now() - started).toBeLessThan(LIMIT_MS);
    }, LIMIT_MS * 2);
  }
});

// Security review: a .gitignore that matches committed source must not hide it from the code agents.
describe("a .gitignore cannot hide committed code", () => {
  it("still reports an unauthenticated delete route that .gitignore claims to ignore", async () => {
    const route = "export async function DELETE(req: Request) {\n  const id = new URL(req.url).searchParams.get(\"id\")\n  await db.user.delete({ where: { id } })\n  return Response.json({})\n}\n";
    const files = memFiles({ ".gitignore": "app/\n", "app/api/users/route.ts": route });
    const r = await runScan({ mode: "static", targetLabel: ".", files, agents: SQUAD });
    expect(r.findings.map((f) => f.ruleId)).toContain("AUTH-002");
  });
});
