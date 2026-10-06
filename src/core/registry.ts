import type { Agent } from "./types.js";
import { agent as aiGuard } from "../agents/ai-guard/index.js";
import { agent as authAuditor } from "../agents/auth-auditor/index.js";
import { agent as databaseGuard } from "../agents/database-guard/index.js";
import { agent as injectionHunter } from "../agents/injection-hunter/index.js";
import { agent as pyGuard } from "../agents/py-guard/index.js";
import { agent as recon } from "../agents/recon/index.js";
import { agent as secretsHunter } from "../agents/secrets-hunter/index.js";
import { agent as supplyChain } from "../agents/supply-chain/index.js";
import { agent as webHardener } from "../agents/web-hardener/index.js";

/** The squad, in roster order. Recon is profiled separately by the orchestrator. */
export const SQUAD: readonly Agent[] = [
  recon,
  secretsHunter,
  databaseGuard,
  authAuditor,
  webHardener,
  supplyChain,
  aiGuard,
  injectionHunter,
  pyGuard,
];
