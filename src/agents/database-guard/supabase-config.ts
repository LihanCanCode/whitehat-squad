import { lineOf, makeFinding } from "../../core/finding.js";
import type { Evidence, Finding, ScanContext } from "../../core/types.js";
import { AGENT_ID } from "./fixes.js";
import { anonymousFix, verifyJwtFix } from "./fixes-extra.js";
import type { PolicyInfo, SqlModel } from "./sql-model.js";
import { IDENTITY_FN, isAuthOnlyPolicy, isTrivialTrue } from "./sql-util.js";
import { parseToml } from "./toml.js";
import type { TomlSection } from "./toml.js";

/** supabase/config.toml analysis: DB-020 (verify_jwt = false), DB-021 (anonymous sign-ins), public buckets (DB-007). */

export interface SupabaseConfig {
  readonly path: string;
  /** Directory holding config.toml, e.g. "supabase". */
  readonly dir: string;
  readonly toml: Map<string, TomlSection>;
}

const CONFIG_PATH = /(^|\/)supabase\/config\.toml$/;
const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const MAX_CODE_FILES = 2000;
const FUNCTION_FILE = /\.(?:[cm]?[jt]sx?)$/;
const RESOLVE_SUFFIXES = ["", ".ts", ".js", ".mjs", ".tsx", "/index.ts", "/index.js"];

const AUTH_MARKERS = new RegExp([
  String.raw`\bauth\s*\.\s*getUser\s*\(`,
  String.raw`\bgetClaims\s*\(`,
  String.raw`\bjwtVerify\s*\(`,
  String.raw`\bconstructEvent(?:Async)?\s*\(`,
  String.raw`\btimingSafeEqual\b`,
  String.raw`\bcrypto\s*\.\s*subtle\s*\.\s*verify\s*\(`,
  String.raw`new\s+Webhook\s*\([^)]*\)\s*\.\s*verify\s*\(`,
].join("|"));
const SECRET_HEADER = /headers\s*\.\s*get\s*\(\s*["'`](?:authorization|x-[\w-]*(?:signature|secret|token|key)|stripe-signature|x-hub-signature[\w-]*)["'`]\s*\)/i;
const ENV_SECRET = /Deno\s*\.\s*env\s*\.\s*get\s*\(/;
const COMPARISON = /[!=]==?/;

export async function loadConfigs(ctx: ScanContext): Promise<SupabaseConfig[]> {
  const out: SupabaseConfig[] = [];
  for (const path of [...ctx.files.paths].filter((p) => CONFIG_PATH.test(p)).sort()) {
    const text = await ctx.files.read(path);
    if (text !== null) out.push({ path, dir: path.slice(0, -"/config.toml".length), toml: parseToml(text) });
  }
  return out;
}

/** Adds `[storage.buckets.X] public = true` to the model; SQL declarations of the same bucket win. */
export function addConfigBuckets(model: SqlModel, configs: readonly SupabaseConfig[]): void {
  for (const c of configs) {
    for (const [name, section] of c.toml) {
      if (!name.startsWith("storage.buckets.") || section.values["public"] !== true) continue;
      const bucket = name.slice("storage.buckets.".length);
      if (!bucket || model.buckets.has(bucket)) continue;
      model.buckets.set(bucket, {
        file: c.path, line: section.lines["public"] ?? section.line, snippet: `[storage.buckets.${bucket}] public = true`,
        name: bucket, isPublic: true, source: "config",
      });
    }
  }
}

function normalize(path: string): string {
  const out: string[] = [];
  for (const part of path.split("/")) {
    if (part === "..") out.pop();
    else if (part && part !== ".") out.push(part);
  }
  return out.join("/");
}

const MAX_IMPORT_DEPTH = 3;
const MAX_FUNCTION_FILES = 25;

/** Source of an edge function: its folder, its configured entrypoint and relative imports (a few levels). */
async function functionSource(ctx: ScanContext, cfg: SupabaseConfig, name: string, entrypoint: unknown): Promise<string | null> {
  const known = new Set(ctx.files.paths);
  const folder = `${cfg.dir}/functions/${name}/`;
  const files = new Set(ctx.files.paths.filter((p) => p.startsWith(folder) && FUNCTION_FILE.test(p)));
  if (typeof entrypoint === "string") {
    const e = normalize(`${cfg.dir}/${entrypoint}`);
    if (known.has(e)) files.add(e);
  }
  if (files.size === 0) return null;
  // Follow relative imports a few levels deep: shared auth often lives in _shared/x.ts, which itself
  // imports the token/secret checks (public-repo study: a function -> orgAuth.ts -> auth.ts chain).
  const seen = new Set<string>();
  let frontier = [...files].sort();
  let text = "";
  for (let depth = 0; depth <= MAX_IMPORT_DEPTH && frontier.length > 0 && seen.size < MAX_FUNCTION_FILES; depth++) {
    const next: string[] = [];
    for (const f of frontier) {
      if (seen.has(f) || seen.size >= MAX_FUNCTION_FILES) continue;
      seen.add(f);
      const body = (await ctx.files.read(f)) ?? "";
      text += `\n${body}`;
      const dir = f.slice(0, f.lastIndexOf("/"));
      for (const imp of body.matchAll(/(?:from|import)\s{0,5}\(?\s{0,5}["'](\.{1,2}\/[^"'\n]{1,200})["']/g)) {
        const base = normalize(`${dir}/${imp[1] as string}`);
        const hit = RESOLVE_SUFFIXES.map((s) => base + s).find((p) => known.has(p) && FUNCTION_FILE.test(p));
        if (hit && !seen.has(hit)) next.push(hit);
      }
    }
    frontier = next;
  }
  return text;
}

function authenticatesItself(source: string): boolean {
  return AUTH_MARKERS.test(source) || (SECRET_HEADER.test(source) && ENV_SECRET.test(source) && COMPARISON.test(source));
}

async function ruleVerifyJwt(ctx: ScanContext, cfg: SupabaseConfig, target: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const [section, s] of cfg.toml) {
    if (!section.startsWith("functions.") || s.values["verify_jwt"] !== false) continue;
    const name = section.slice("functions.".length);
    const source = await functionSource(ctx, cfg, name, s.values["entrypoint"]);
    if (source === null || authenticatesItself(source)) continue;
    // Calibrated on public repos: many open functions are public by design (sitemap, public forms).
    // The dangerous ones bypass RLS with the service-role key; the rest are worth a look, not an alarm.
    const serviceRole = /SERVICE_ROLE|service_role/.test(source);
    out.push(makeFinding({
      ruleId: "DB-020", agentId: AGENT_ID, target, severity: serviceRole ? "high" : "medium", ...(serviceRole ? {} : { confidence: "medium" as const }), cwe: "CWE-306",
      title: `Edge Function "${name}" is callable by anyone (verify_jwt = false)`,
      explanation: `supabase/config.toml turns off JWT verification for the Edge Function "${name}", and its code never authenticates the caller (no auth.getUser / getClaims, no webhook signature or shared-secret check). Anyone on the internet who finds the function URL can invoke it and burn your quota.` +
        (serviceRole
          ? " It uses the service-role key, which bypasses Row Level Security, so callers act with full database access."
          : " If it is public by design (a sitemap, a public form), make sure it only does what an anonymous visitor may do."),
      evidence: [{ file: cfg.path, line: s.lines["verify_jwt"] ?? s.line, snippet: `[${section}] verify_jwt = false` }],
      fix: verifyJwtFix(name),
    }));
  }
  return out;
}

function candidatePolicies(model: SqlModel): PolicyInfo[] {
  return model.policies.filter((p) => {
    if (p.restrictive || !p.roles.includes("authenticated")) return false;
    const expr = `${p.using ?? ""} ${p.check ?? ""}`;
    if (/is_anonymous/i.test(expr)) return false;
    return isTrivialTrue(p.using) || isTrivialTrue(p.check) || isAuthOnlyPolicy(p) || !IDENTITY_FN.test(expr);
  });
}

async function anonymousSource(ctx: ScanContext, configs: readonly SupabaseConfig[]): Promise<Evidence | null> {
  for (const c of configs) {
    const auth = c.toml.get("auth");
    if (auth?.values["enable_anonymous_sign_ins"] === true) {
      return { file: c.path, line: auth.lines["enable_anonymous_sign_ins"] ?? auth.line, snippet: "[auth] enable_anonymous_sign_ins = true" };
    }
  }
  let scanned = 0;
  for (const path of ctx.files.paths) {
    if (!CODE_FILE.test(path) || path.includes("node_modules/")) continue;
    if (++scanned > MAX_CODE_FILES) break;
    const text = await ctx.files.read(path);
    const hit = text === null ? null : /\bsignInAnonymously\s*\(/.exec(text);
    if (text !== null && hit) return { file: path, line: lineOf(text, hit.index), snippet: "signInAnonymously()" };
  }
  return null;
}

async function ruleAnonymous(ctx: ScanContext, configs: readonly SupabaseConfig[], model: SqlModel, target: string): Promise<Finding[]> {
  const policies = candidatePolicies(model);
  const first = policies[0];
  if (!first) return [];
  const source = await anonymousSource(ctx, configs);
  if (!source) return [];
  const more = policies.slice(0, 3).map((p) => ({ file: p.file, line: p.line, snippet: p.snippet }));
  return [makeFinding({
    ruleId: "DB-021", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-287",
    title: `Anonymous sign-ins are enabled and ${policies.length} "to authenticated" polic${policies.length === 1 ? "y does" : "ies do"} not exclude them`,
    explanation: `Anonymous sign-ins are on (${source.file}), and Supabase gives every anonymous visitor the "authenticated" role. The policy "${first.name}" on ${first.tableKey} is granted "to authenticated" without an is_anonymous check and without tying rows to the caller, so a visitor who never registered gets the same access as a real user: no email, no friction, unlimited throwaway accounts.`,
    evidence: [...more, source],
    fix: anonymousFix(first.tableKey, first.name),
  })];
}

export async function analyzeConfig(
  ctx: ScanContext, configs: readonly SupabaseConfig[], model: SqlModel, target: string,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const cfg of configs) out.push(...(await ruleVerifyJwt(ctx, cfg, target)));
  out.push(...(await ruleAnonymous(ctx, configs, model, target)));
  return out;
}
