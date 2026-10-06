/** Regenerates docs/rules.md from the rule catalog. Run: npx tsx scripts/gen-rules.ts */
import { writeFileSync } from "node:fs";
import { ALL_RULES } from "../src/rules/catalog.js";
import { renderRulesDoc } from "../src/rules/render-docs.js";

writeFileSync(new URL("../docs/rules.md", import.meta.url), renderRulesDoc(ALL_RULES));
process.stdout.write(`docs/rules.md: ${ALL_RULES.length} rules\n`);
