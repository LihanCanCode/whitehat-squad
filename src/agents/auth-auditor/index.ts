import { guardMatches } from "../../core/source/index.js";
import type { Agent, Finding, ScanContext } from "../../core/types.js";
import { buildFileCtx, usesAuthProvider, type FileCtx, type Project } from "./context.js";
import { analyzeMiddleware } from "./middleware.js";
import { isViteConfigPath, isMiddlewarePath } from "./patterns.js";
import { toFinding, type Raised } from "./report.js";
import { clientControlledRole, clientOnlyGuard, serviceRoleInClient } from "./rules-client.js";
import { jwtMisuse } from "./rules-jwt.js";
import { idorHandlers, unauthenticatedHandlers, unsignedStripeWebhooks } from "./rules-server.js";
import { NEW_RULE_PASSES } from "./rules-new.js";
import { operationsRoutes } from "./rules-ops.js";
import { loadSensitiveTargets } from "./sensitive.js";
import { AGENT_ID, fileUnit, isScannable } from "./util.js";

async function loadFiles(ctx: ScanContext, hasVite: boolean): Promise<FileCtx[]> {
  const out: FileCtx[] = [];
  for (const path of ctx.files.paths) {
    // Not .gitignore: committed code is real code even when a (possibly hostile) .gitignore matches it.
    if (!isScannable(path)) continue;
    const raw = await ctx.files.read(path);
    if (raw !== null) out.push(buildFileCtx(path, raw, hasVite));
  }
  return out;
}

async function describeProject(ctx: ScanContext, files: readonly FileCtx[], hasVite: boolean): Promise<Project> {
  const middleware = files.filter((f) => isMiddlewarePath(f.path)).map((f) => analyzeMiddleware(f.src));
  return {
    hasVite,
    middleware,
    hasMiddlewareRateLimit: middleware.some((m) => m.rateLimits),
    hasAuthProvider: usesAuthProvider(files),
    hasServerAuth: files.some((f) => f.isServer && f.kind !== "middleware" && guardMatches(f.src, fileUnit(f.src), "auth").length > 0),
    hasUnguardedServerData: false,
    hasServerHandlers: files.some((f) => f.isServer && f.handlers.length > 0),
    sensitiveTargets: await loadSensitiveTargets(ctx),
  };
}

function dedupe(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
}

export const agent: Agent = {
  id: AGENT_ID,
  name: "AuthAuditor",
  role: "Finds missing or client-side-only auth, IDOR-prone routes, JWT misuse and weak credential handling",
  modes: ["static"],
  async run(ctx) {
    const hasVite = ctx.files.paths.some(isViteConfigPath);
    const files = await loadFiles(ctx, hasVite);
    const project = await describeProject(ctx, files, hasVite);
    const raised: Raised[] = [];

    const newRules = files.flatMap((f) => NEW_RULE_PASSES.flatMap((pass) => pass(f, project)));
    for (const f of files) {
      const ops = operationsRoutes(f, project);
      const superseded = new Set(ops.map((o) => o.unit));
      raised.push(...ops.map((o) => o.raised));
      raised.push(...unauthenticatedHandlers(f, project, superseded), ...idorHandlers(f), ...unsignedStripeWebhooks(f));
    }
    project.hasUnguardedServerData = raised.some((r) => r.ruleId === "AUTH-002");
    for (const f of files) {
      raised.push(...clientOnlyGuard(f, project), ...clientControlledRole(f), ...serviceRoleInClient(f, project));
      raised.push(...jwtMisuse(f, ctx.registerSecret));
    }
    raised.push(...newRules);
    return dedupe(raised.map(toFinding));
  },
};
