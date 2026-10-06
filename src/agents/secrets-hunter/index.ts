import path from "node:path";
import { getLiveAssets } from "../../core/live-assets.js";
import type { Agent, Finding, ScanContext } from "../../core/types.js";
import { dockerContextFinding, literalSecretFinding, weakSecretFinding } from "./config-findings.js";
import { findConfigSecrets, WEAK_SECRET_RULE_ID } from "./config-secrets.js";
import { contextCopyConfidence, dockerignoreExcludesEnv, findContextCopies } from "./docker-context.js";
import { AGENT_ID, matchToFinding, trackedEnvFinding } from "./findings.js";
import { structuredKind } from "./structured-config.js";
import { scanGitHistory } from "./history.js";
import { findSecrets, isEnvFile, isEnvTemplate, isPlaceholder, isSkippedPath, isSupplyChainOwnedPath } from "./scanner.js";

const READ_BATCH = 16;
const MIN_REGISTER_LENGTH = 8;
const ENV_ASSIGNMENT = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$/gm;
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)/;
// A connection string pointing only at the developer's own machine (the Postgres/PGLite default
// local-dev credential, for example) is not an exposure worth rotating.
const LOCAL_ONLY_URL = /^\w+:\/\/[^@/]*@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?::\d+)?\//i;
// A short boolean/numeric flag (NEXT_TELEMETRY_DISABLED=1, DEBUG=true) is not a secret, regardless
// of its variable name having no public prefix.
const TRIVIAL_VALUE = /^(?:true|false|\d+|on|off|yes|no)$/i;
// isPlaceholder() only catches "your_secret"/"your_key" etc. directly; a boilerplate's comment
// also leaves values like "your_clerk_secret_key" where another word sits in between.
const LOOKS_LIKE_PLACEHOLDER = /^your[_-]/i;

/** Private-looking assignments: not a NEXT_PUBLIC_-style var, and not empty/placeholder/local-only. */
function sensitiveAssignmentCount(text: string): number {
  let n = 0;
  for (const m of text.matchAll(ENV_ASSIGNMENT)) {
    const name = m[1] ?? "";
    const value = (m[2] ?? "").trim().replace(/^["']|["']$/g, "");
    if (
      !PUBLIC_PREFIX.test(name) && value && !isPlaceholder(value) && !LOCAL_ONLY_URL.test(value) &&
      !TRIVIAL_VALUE.test(value) && !LOOKS_LIKE_PLACEHOLDER.test(value)
    ) n++;
  }
  return n;
}

function targetOf(ctx: ScanContext): string {
  return ctx.root ?? ctx.target?.href ?? ".";
}

async function scanStatic(ctx: ScanContext): Promise<{ findings: Finding[]; trackedValues: Set<string> }> {
  const findings: Finding[] = [];
  const trackedValues = new Set<string>();
  const target = targetOf(ctx);
  // .npmrc / .yarnrc.yml tokens are reported by the supply-chain agent (SUP-008); skipping them avoids a double report.
  const paths = ctx.files.paths.filter((p) => !isSkippedPath(p) && !isSupplyChainOwnedPath(p));

  for (let i = 0; i < paths.length; i += READ_BATCH) {
    const batch = paths.slice(i, i + READ_BATCH);
    const contents = await Promise.all(batch.map((p) => ctx.files.read(p)));
    batch.forEach((file, idx) => {
      const text = contents[idx];
      const envFile = isEnvFile(file) && !isEnvTemplate(file);
      const ignored = envFile && ctx.files.isIgnored(file);
      if (envFile && !ignored) {
        // A tracked .env that holds only public (NEXT_PUBLIC_/VITE_/...) vars or placeholders
        // is a deliberate template, not an exposed secret file (common in starter boilerplates).
        const count = text ? sensitiveAssignmentCount(text) : 0;
        if (count > 0) findings.push(trackedEnvFinding(file, count, target));
      }
      if (!text) return;
      const seen = new Set<string>();
      const configMatches = findConfigSecrets(text, file, { ignoredEnv: ignored });
      const weakValues = new Set(configMatches.filter((c) => c.ruleId === WEAK_SECRET_RULE_ID).map((c) => c.value));
      const matches = findSecrets(text, file, { generic: true, publicOnly: ignored });
      for (const m of matches) {
        if (m.isGeneric && weakValues.has(m.value)) continue;
        if (seen.has(m.value)) continue;
        seen.add(m.value);
        ctx.registerSecret(m.value);
        if (!ignored) trackedValues.add(m.value);
        findings.push(matchToFinding(m, { kind: "static", target, file }));
      }
      const taken = new Set(seen);
      const reported = new Set<string>();
      for (const c of configMatches) {
        const key = `${c.ruleId}|${c.name}|${c.line}`;
        if (taken.has(c.value) || reported.has(key)) continue;
        reported.add(key);
        // Values under 8 chars are known defaults that cannot be scrubbed from text safely anyway.
        if (c.value.length >= MIN_REGISTER_LENGTH) ctx.registerSecret(c.value);
        if (!ignored) trackedValues.add(c.value);
        findings.push(c.ruleId === WEAK_SECRET_RULE_ID ? weakSecretFinding(c, file, target) : literalSecretFinding(c, file, target));
      }
    });
  }
  findings.push(...(await scanDockerfiles(ctx, paths, target)));
  return { findings, trackedValues };
}

const dirOf = (file: string): string => path.posix.dirname(file);

/** The .dockerignore files that can apply: BuildKit's per-Dockerfile one, else the sibling and the root one. */
function dockerignoreCandidates(file: string, known: ReadonlySet<string>): string[] {
  const specific = `${file}.dockerignore`;
  if (known.has(specific)) return [specific];
  return [...new Set([path.posix.join(dirOf(file), ".dockerignore"), ".dockerignore"])].filter((p) => known.has(p));
}

async function scanDockerfiles(ctx: ScanContext, paths: readonly string[], target: string): Promise<Finding[]> {
  const dockerfiles = paths.filter((p) => structuredKind(p) === "dockerfile");
  if (dockerfiles.length === 0) return [];
  const known = new Set(ctx.files.paths);
  const envFiles = ctx.files.paths.filter((p) => isEnvFile(p) && !isEnvTemplate(p));
  const hasOtherEnv = envFiles.some((p) => path.posix.basename(p) !== ".env");
  const findings: Finding[] = [];
  for (const file of dockerfiles) {
    const text = await ctx.files.read(file);
    const { copies, stageCount } = text ? findContextCopies(text) : { copies: [], stageCount: 1 };
    if (copies.length === 0) continue;
    const ignores = await Promise.all(dockerignoreCandidates(file, known).map((p) => ctx.files.read(p)));
    if (ignores.some((c) => c !== null && dockerignoreExcludesEnv(c, hasOtherEnv))) continue;
    const copy = copies.find((c) => c.stage === stageCount - 1) ?? copies[0];
    if (!copy) continue;
    findings.push(dockerContextFinding(copy, file, contextCopyConfidence(copy, stageCount, envFiles.length > 0), target));
  }
  return findings;
}

async function scanLive(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const target = targetOf(ctx);
  const assets = await getLiveAssets(ctx);
  const seen = new Set<string>();
  for (const asset of [...(assets.html ? [assets.html] : []), ...assets.scripts]) {
    for (const m of findSecrets(asset.body, asset.url, { generic: false })) {
      const key = `${asset.url}|${m.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      ctx.registerSecret(m.value);
      findings.push(matchToFinding(m, { kind: "live", target, url: asset.url }));
    }
  }
  return findings;
}

async function scanHistory(ctx: ScanContext, trackedValues: ReadonlySet<string>): Promise<Finding[]> {
  if (!ctx.options.gitHistory || !ctx.root) return [];
  const hits = await scanGitHistory(ctx.root, trackedValues);
  return hits.map((h) => {
    ctx.registerSecret(h.match.value);
    return matchToFinding(h.match, {
      kind: "history", target: targetOf(ctx), file: h.file, line: h.line, commit: h.commit,
    });
  });
}

export const agent: Agent = {
  id: AGENT_ID,
  name: "SecretsHunter",
  role: "Hunts leaked API keys, tokens and committed .env files",
  modes: ["static", "live"],
  async run(ctx) {
    if (ctx.mode === "live") return scanLive(ctx);
    const { findings, trackedValues } = await scanStatic(ctx);
    return [...findings, ...(await scanHistory(ctx, trackedValues))];
  },
};
