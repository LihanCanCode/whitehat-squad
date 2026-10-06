import { RULES as aiGuard } from "../agents/ai-guard/rules.meta.js";
import { RULES as authAuditor } from "../agents/auth-auditor/rules.meta.js";
import { RULES as databaseGuard } from "../agents/database-guard/rules.meta.js";
import { RULES as injectionHunter } from "../agents/injection-hunter/rules.meta.js";
import { RULES as pyGuard } from "../agents/py-guard/rules.meta.js";
import { RULES as aiReview } from "../review/rules.meta.js";
import { RULES as recon } from "../agents/recon/rules.meta.js";
import { RULES as secretsHunter } from "../agents/secrets-hunter/rules.meta.js";
import { RULES as supplyChain } from "../agents/supply-chain/rules.meta.js";
import { RULES as webHardener } from "../agents/web-hardener/rules.meta.js";
import type { RuleMeta } from "./types.js";

/** Every rule the squad can raise, across all agents, in a stable order. */
export const ALL_RULES: readonly RuleMeta[] = [
  ...recon,
  ...secretsHunter,
  ...databaseGuard,
  ...authAuditor,
  ...webHardener,
  ...supplyChain,
  ...aiGuard,
  ...injectionHunter,
  ...pyGuard,
  ...aiReview,
];

const BY_ID = new Map(ALL_RULES.map((r) => [r.id, r]));

export function ruleMeta(id: string): RuleMeta | undefined {
  return BY_ID.get(id);
}

const DOCS_BASE = "https://github.com/LihanCanCode/whitehat-squad/blob/main/docs/rules.md";

/** Stable documentation anchor for one rule (docs/rules.md is generated from this catalog). */
export function ruleHelpUri(id: string): string {
  return `${DOCS_BASE}#${id.toLowerCase()}`;
}

/** Rules a normal scan runs: everything except the opt-in, LLM-assisted `whsquad review` classes. */
export const DETERMINISTIC_RULES: readonly RuleMeta[] = ALL_RULES.filter((r) => r.agent !== "ai-review");
