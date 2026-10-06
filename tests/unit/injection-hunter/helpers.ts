import { agent } from "../../../src/agents/injection-hunter/index.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext } from "../../helpers/memfs.js";

export async function scan(files: Record<string, string>): Promise<Finding[]> {
  return agent.run(memContext(files));
}

/** Scan one file (an Express-style server.js by default). */
export async function scanOne(code: string, path = "server.js"): Promise<Finding[]> {
  return scan({ [path]: code });
}

/** Wrap statements in an Express POST handler. */
export const express = (body: string, imports = ""): string =>
  `${imports}\nconst app = require("express")();\napp.post("/x", async (req, res) => {\n${body}\n});\n`;

/** Wrap statements in a Next.js route handler. */
export const route = (body: string, imports = "", method = "POST"): string =>
  `${imports}\nexport async function ${method}(req: Request) {\n${body}\n}\n`;

export const only = (fs: Finding[], id: string): Finding[] => fs.filter((f) => f.ruleId === id);
export const idsOf = (fs: Finding[]): string[] => [...new Set(fs.map((f) => f.ruleId))].sort();
