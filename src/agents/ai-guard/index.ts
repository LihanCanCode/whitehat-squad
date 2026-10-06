import { isGeneratedPath, isTestPath, isVendorPath, lineOf, snippetAt } from "../../core/source/index.js";
import type { Agent, Finding, ScanContext } from "../../core/types.js";
import { buildCtx } from "./context.js";
import type { Ctx, Hit, ProjectEnv } from "./context.js";
import { AGENT_ID, buildFinding } from "./findings.js";
import { detectUncappedAgentLoop, detectUnboundedUsage, detectUnprotectedRoute } from "./rules-abuse.js";
import { detectClientLlm, detectPublicKeyVar, PUBLIC_KEY } from "./rules-exposure.js";
import { detectIndirectInjection, detectSystemPromptInjection } from "./rules-injection.js";
import { detectUnsafeOutput } from "./rules-output.js";
import { detectMcpToolSinks, detectUnscopedVectorQuery } from "./rules-tools.js";

const CODE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const ENV_FILE = /(?:^|\/)\.env(?:\.[\w.-]+)?$/;
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults?)$/;
const MAX_FILE_BYTES = 300_000;
const SECRET_LITERAL = /sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|gsk_[A-Za-z0-9]{20,}/g;
const MAX_SNIPPET = 200;
const MIDDLEWARE_PROTECTION = /\bauth\b|clerk|ratelimit|rate-limit|limiter|session|jwt|getToken/i;
const AUTH_DEPENDENCY = /["'](?:@clerk\/[\w-]+|next-auth|@auth\/[\w-]+|better-auth|lucia|@supabase\/(?:ssr|auth-helpers-[\w-]+|supabase-js)|@kinde-oss\/[\w-]+|firebase|firebase-admin|passport|@workos-inc\/[\w-]+|@stytch\/[\w-]+)["']\s*:/;

async function detectEnv(ctx: ScanContext): Promise<ProjectEnv> {
  const paths = ctx.files.paths;
  const frameworks = ctx.stack.frameworks;
  const viteLike =
    paths.some((p) => /(?:^|\/)vite\.config\.[cm]?[jt]s$/.test(p)) ||
    frameworks.includes("vite") ||
    (frameworks.includes("react") && !frameworks.some((x) => x === "next" || x === "remix" || x === "express"));
  let middlewareProtected = false;
  for (const p of paths.filter((x) => /(?:^|\/)(?:middleware|proxy)\.[cm]?[jt]s$/.test(x))) {
    const text = await ctx.files.read(p);
    if (text && MIDDLEWARE_PROTECTION.test(text)) middlewareProtected = true;
  }
  let hasUserAuth = false;
  for (const p of paths.filter((x) => /(?:^|\/)package\.json$/.test(x) && !x.includes("node_modules/"))) {
    const text = await ctx.files.read(p);
    if (text && AUTH_DEPENDENCY.test(text)) hasUserAuth = true;
  }
  return { viteLike, middlewareProtected, hasUserAuth };
}

function detect(c: Ctx): Hit[] {
  return [
    ...detectClientLlm(c),
    ...detectSystemPromptInjection(c),
    ...detectUnsafeOutput(c),
    ...detectUnprotectedRoute(c, c.env),
    ...detectUnboundedUsage(c),
    ...detectIndirectInjection(c),
    ...detectPublicKeyVar(c),
    ...detectMcpToolSinks(c),
    ...detectUnscopedVectorQuery(c),
    ...detectUncappedAgentLoop(c),
  ];
}

function register(snippet: string, ctx: ScanContext): void {
  for (const secret of snippet.matchAll(SECRET_LITERAL)) ctx.registerSecret(secret[0]);
}

function codeFindings(c: Ctx, ctx: ScanContext): Finding[] {
  return detect(c).map((hit) => {
    const snippet = snippetAt(c.src, hit.index, MAX_SNIPPET);
    register(snippet, ctx);
    return buildFinding(hit, c.path, lineOf(c.src, hit.index), snippet);
  });
}

/** AI-007 in `.env*` files: a model key under a public prefix is bundled into the browser. */
function envFindings(path: string, raw: string, ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  const template = ENV_TEMPLATE.test(path);
  const lines = raw.split(/\r?\n/);
  lines.forEach((text, i) => {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/.exec(text);
    if (!m || /^\s*#/.test(text)) return;
    PUBLIC_KEY.lastIndex = 0;
    const key = PUBLIC_KEY.exec(m[1] ?? "");
    if (!key || key[0] !== m[1]) return;
    const value = (m[2] ?? "").replace(/^["']|["']\s*(?:#.*)?$/g, "").trim();
    const filled = value !== "" && !/^(?:your[-_\w]*|xxx+|\.\.\.|<.*>|changeme|todo)$/i.test(value);
    const snippet = text.trim().slice(0, MAX_SNIPPET);
    register(snippet, ctx);
    out.push(
      buildFinding(
        {
          ruleId: "AI-007",
          index: 0,
          severity: template ? "medium" : filled ? "critical" : "high",
          confidence: template ? "medium" : filled ? "high" : "medium",
          variant: key[0],
        },
        path,
        i + 1,
        snippet,
      ),
    );
  });
  return out;
}

export const agent: Agent = {
  id: AGENT_ID,
  name: "AIGuard",
  role: "Reviews LLM usage for prompt injection, unsafe output handling, key exposure and cost abuse",
  modes: ["static"],
  async run(ctx) {
    const env = await detectEnv(ctx);
    const seen = new Set<string>();
    const findings: Finding[] = [];
    const add = (list: Finding[]): void => {
      for (const finding of list) {
        if (seen.has(finding.id)) continue;
        seen.add(finding.id);
        findings.push(finding);
      }
    };
    for (const path of ctx.files.paths) {
      if (isVendorPath(path) || isGeneratedPath(path) || isTestPath(path)) continue;
      const isCode = CODE_FILE.test(path);
      if (!isCode && !ENV_FILE.test(path)) continue;
      const raw = await ctx.files.read(path);
      if (raw === null || raw.length > MAX_FILE_BYTES) continue;
      add(isCode ? codeFindings(buildCtx(path, raw, env), ctx) : envFindings(path, raw, ctx));
    }
    return findings.sort((a, b) => (a.evidence[0]?.file ?? "").localeCompare(b.evidence[0]?.file ?? "") || (a.evidence[0]?.line ?? 0) - (b.evidence[0]?.line ?? 0));
  },
};
