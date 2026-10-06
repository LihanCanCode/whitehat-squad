import { agent } from "../../../src/agents/py-guard/index.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext } from "../../helpers/memfs.js";

export async function scan(files: Record<string, string>): Promise<Finding[]> {
  return agent.run(memContext(files));
}

/** Scan a single app.py (with Flask/FastAPI/Django imports provided by the caller). */
export async function scanOne(code: string, path = "app.py"): Promise<Finding[]> {
  return scan({ [path]: code });
}

export const only = (fs: Finding[], id: string): Finding[] => fs.filter((f) => f.ruleId === id);
export const idsOf = (fs: Finding[]): string[] => [...new Set(fs.map((f) => f.ruleId))].sort();
