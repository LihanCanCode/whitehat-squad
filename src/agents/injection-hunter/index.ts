import { isGeneratedPath, isTestPath, isVendorPath } from "../../core/source/index.js";
import type { Agent, Finding } from "../../core/types.js";
import { commandFindings } from "./command.js";
import { evalFindings } from "./eval.js";
import { nosqlFindings } from "./nosql.js";
import { pathFindings } from "./path.js";
import { postgrestFindings } from "./postgrest.js";
import { redirectFindings } from "./redirect.js";
import { createCtx } from "./shared.js";
import type { FileCtx, ProjectFacts } from "./shared.js";
import { sqlFindings } from "./sql.js";
import { ssrfFindings } from "./ssrf.js";

const CODE_FILE = /\.(?:[cm]?[jt]sx?)$/i;
const MAX_FILE_BYTES = 1_500_000;
const MONGO_SANITIZE = /express-mongo-sanitize|mongo-sanitize|sanitizeFilter/;

const RULES: ReadonlyArray<(ctx: FileCtx) => Finding[]> = [
  sqlFindings,
  postgrestFindings,
  commandFindings,
  ssrfFindings,
  redirectFindings,
  pathFindings,
  nosqlFindings,
  evalFindings,
];

function isCandidate(path: string): boolean {
  return CODE_FILE.test(path) && !path.endsWith(".d.ts") && !path.includes("node_modules/") && !isTestPath(path) && !isGeneratedPath(path) && !isVendorPath(path);
}

/** Minified bundles: very long lines, almost no newlines. */
function looksMinified(text: string): boolean {
  return text.length > 20_000 && text.split("\n").length < text.length / 1_000;
}

export const agent: Agent = {
  id: "injection-hunter",
  name: "InjectionHunter",
  role: "Traces request input into SQL, shell, URLs, redirects and file paths",
  modes: ["static"],
  async run(ctx) {
    const files: Array<{ path: string; text: string }> = [];
    for (const path of ctx.files.paths.filter(isCandidate)) {
      const text = await ctx.files.read(path);
      if (text !== null && text.length <= MAX_FILE_BYTES && !looksMinified(text)) files.push({ path, text });
    }
    const project: ProjectFacts = { sanitizesMongo: files.some((f) => MONGO_SANITIZE.test(f.text)) };
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of files) {
      const fileCtx = createCtx(file.path, file.text, project);
      for (const rule of RULES) {
        for (const f of rule(fileCtx)) {
          const e = f.evidence[0];
          const key = `${f.ruleId}|${e?.file}|${e?.line}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push(f);
        }
      }
    }
    return findings;
  },
};
