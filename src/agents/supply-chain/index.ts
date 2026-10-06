import { lineOf } from "../../core/finding.js";
import type { Agent, Evidence, Finding, ScanContext } from "../../core/types.js";
import { redactSecret } from "../../safety/redact.js";
import { ADVISORY_PACKAGES } from "../../data/advisories.js";
import { findRisky } from "../../data/risky-packages.js";
import {
  findHiddenText, isAgentConfigPath, isMcpConfigPath, literalSecretEnv, readMcpServers, unpinnedLauncher,
} from "./agent-config.js";
import { collectSignals, findingsForVersion } from "./framework-advisories.js";
import {
  dependencyScriptsFinding, noLockfileFinding, npmrcTokenFinding, ownInstallScriptFinding,
  riskyFinding, slopFinding, specFinding, typosquatFinding, unreadableFinding,
} from "./findings.js";
import {
  distTagFinding, hiddenTextFinding, mcpSecretFinding, overrideFinding, packageConfigFinding, unpinnedMcpFinding, workflowFinding,
} from "./findings-extra.js";
import { LOCKFILE_NAMES, parseLockfile, type LockInfo } from "./lockfiles.js";
import { parseManifest, type Dep, type Manifest } from "./manifest.js";
import { checkTyposquat, slopBase } from "./names.js";
import { PACKAGE_CONFIG_FILES, packageConfigIssues } from "./package-config.js";
import { isRemoteExec } from "./remote-exec.js";
import { exactVersion } from "./semver.js";
import { classifySpec, distTagIssue, sourceSpec } from "./spec.js";
import { isWorkflowPath, workflowIssues } from "./workflows.js";

export { isRemoteExec } from "./remote-exec.js";

const MAX_FILE_BYTES_HINT = 5_000_000;

/** Packages whose install scripts are well known and legitimate (native builds, browser downloads). */
const KNOWN_BUILD_PACKAGES: ReadonlySet<string> = new Set([
  "esbuild", "sharp", "@swc/core", "core-js", "protobufjs", "bcrypt", "sqlite3", "better-sqlite3", "puppeteer",
  "playwright", "prisma", "@prisma/client", "@prisma/engines", "nx", "fsevents", "unrs-resolver", "msw", "husky",
  "cypress", "electron", "canvas", "@parcel/watcher", "lmdb", "msgpackr-extract", "workerd", "@sentry/cli",
  "bufferutil", "utf-8-validate", "@biomejs/biome", "argon2", "@clerk/shared", "@firebase/util", "core-js-pure",
]);

function basename(p: string): string {
  return p.slice(p.lastIndexOf("/") + 1);
}

function inNodeModules(p: string): boolean {
  return p.split("/").includes("node_modules");
}

class LockResolver {
  private readonly cache = new Map<string, LockInfo | null>();
  /** All lockfile paths that exist anywhere in the repo. */
  readonly present: ReadonlySet<string>;

  constructor(private readonly ctx: ScanContext) {
    this.present = new Set(
      ctx.files.paths.filter((p) => LOCKFILE_NAMES.some((l) => l.file === basename(p)) && !inNodeModules(p)),
    );
  }

  /** Parsed lockfile at an exact path; null when its contents are unknown (binary bun.lockb, unreadable or corrupt). */
  async get(path: string): Promise<LockInfo | null> {
    if (!this.cache.has(path)) {
      const kind = LOCKFILE_NAMES.find((l) => l.file === basename(path))?.kind ?? "bun";
      this.cache.set(path, await this.load(path, kind));
    }
    return this.cache.get(path) ?? null;
  }

  /** Nearest lockfile at or above `dir` (monorepos keep one at the root). */
  async nearest(dir: string): Promise<{ file: string; info: LockInfo | null } | null> {
    for (let d = dir; ; d = d.slice(0, Math.max(d.lastIndexOf("/"), 0))) {
      for (const { file } of LOCKFILE_NAMES) {
        const path = d ? `${d}/${file}` : file;
        if (!this.present.has(path)) continue;
        return { file: path, info: await this.get(path) };
      }
      if (d === "") return null;
    }
  }

  private async load(path: string, kind: (typeof LOCKFILE_NAMES)[number]["kind"]): Promise<LockInfo | null> {
    if (basename(path) === "bun.lockb") return null; // binary format: present, contents unknown
    const text = await this.ctx.files.read(path);
    if (text === null) return null;
    try {
      return parseLockfile(path, kind, text);
    } catch {
      return null;
    }
  }
}

interface ScanState {
  readonly locks: LockResolver;
  readonly workspaceNames: ReadonlySet<string>;
  /** name@version already reported as compromised (manifest pin and lockfile entry are one finding). */
  readonly reportedRisky: Set<string>;
  /** Resolved framework versions to check against advisories, keyed name@version. */
  readonly resolved: Map<string, { name: string; version: string; evidence: Evidence }>;
}

function isLocalSpec(spec: string): boolean {
  return /^(?:workspace|file|link):/.test(spec);
}

function lacksProvenance(name: string, info: LockInfo): boolean {
  const entries = info.byName.get(name);
  return !entries || entries.length === 0 || entries.some((e) => !e.hasResolved || !e.hasIntegrity);
}

function scanDep(m: Manifest, dep: Dep, lock: { file: string; info: LockInfo | null } | null, state: ScanState): Finding[] {
  const out: Finding[] = [];
  const evidence = { file: m.file, line: dep.line, snippet: dep.text };
  const bundled = dep.section === "bundledDependencies";

  if (!bundled) {
    const issue = classifySpec(dep.spec, m.dir);
    if (issue && !(dep.section === "peerDependencies" && issue.kind === "wildcard")) out.push(specFinding(m.file, dep, issue));
    const tag = distTagIssue(dep.spec);
    if (tag) out.push(distTagFinding(m.file, dep, tag));
  }
  if (isLocalSpec(dep.spec) || state.workspaceNames.has(dep.name)) return out;

  const typo = checkTyposquat(dep.name);
  if (typo) out.push(typosquatFinding(m.file, dep, typo));

  const base = typo ? null : slopBase(dep.name);
  // A lockfile whose contents are unknown (binary bun.lockb, corrupt) proves nothing either way.
  if (base && (!lock || (lock.info !== null && lacksProvenance(dep.name, lock.info)))) {
    out.push(slopFinding(m.file, dep, base, lock !== null));
  }

  // Only an exactly pinned spec names a version; a range resolves wherever the lockfile says.
  const pinned = exactVersion(dep.spec);
  if (!pinned || bundled) return out;
  const advisory = findRisky(dep.name, pinned);
  if (advisory) {
    state.reportedRisky.add(`${dep.name}@${pinned}`);
    out.push(riskyFinding(m.file, dep.name, pinned, advisory, evidence));
  }
  if (ADVISORY_PACKAGES.has(dep.name) && !lock?.info?.byName.has(dep.name)) {
    state.resolved.set(`${dep.name}@${pinned}`, { name: dep.name, version: pinned, evidence });
  }
  return out;
}

async function scanManifest(m: Manifest, state: ScanState): Promise<Finding[]> {
  const out: Finding[] = [];
  const lock = await state.locks.nearest(m.dir);

  const installed = m.deps.filter((d) => d.section !== "peerDependencies" && d.section !== "bundledDependencies");
  if (installed.length > 0 && !lock) out.push(noLockfileFinding(m.file, installed[0]?.line ?? 1));

  for (const s of m.scripts) {
    if (isRemoteExec(s.command)) out.push(ownInstallScriptFinding(m.file, s.hook, s.command, s.line, s.when));
  }
  for (const entry of m.overrides) {
    const source = sourceSpec(entry.spec);
    if (source) out.push(overrideFinding(m.file, entry, source));
  }
  for (const dep of m.deps) out.push(...scanDep(m, dep, lock, state));
  return out;
}

function scanLockfile(info: LockInfo, state: ScanState): Finding[] {
  const out: Finding[] = [];
  for (const e of info.entries) {
    const key = `${e.name}@${e.version}`;
    const evidence = { file: info.file, snippet: key };
    if (ADVISORY_PACKAGES.has(e.name)) state.resolved.set(key, { name: e.name, version: e.version, evidence });
    const advisory = findRisky(e.name, e.version);
    if (!advisory || state.reportedRisky.has(key)) continue;
    state.reportedRisky.add(key);
    out.push(riskyFinding(info.file, e.name, e.version, advisory, evidence));
  }
  const scripted = [...new Set(info.entries.filter((e) => e.hasInstallScript && !KNOWN_BUILD_PACKAGES.has(e.name)).map((e) => e.name))];
  if (scripted.length > 0) out.push(dependencyScriptsFinding(info.file, scripted.sort()));
  return out;
}

async function scanAdvisories(state: ScanState, ctx: ScanContext, paths: readonly string[]): Promise<Finding[]> {
  if (state.resolved.size === 0) return [];
  const signals = await collectSignals(ctx, paths);
  const out: Finding[] = [];
  for (const { name, version, evidence } of state.resolved.values()) {
    out.push(...findingsForVersion(evidence, name, version, signals));
  }
  return out;
}

const NPMRC_SECRET = /^\s*([^#;\n]*?\b(?:_authToken|_auth|_password))\s*=\s*(\S+)\s*$/;

async function scanPackageConfig(path: string, ctx: ScanContext): Promise<Finding[]> {
  if (ctx.files.isIgnored(path)) return [];
  const text = await ctx.files.read(path);
  if (text === null) return [];
  const out: Finding[] = [];
  if (basename(path) === ".npmrc") {
    text.split(/\r?\n/).forEach((line, i) => {
      const m = NPMRC_SECRET.exec(line);
      const value = m?.[2]?.replace(/^["']|["']$/g, "");
      if (!m || !value || value.includes("${")) return;
      ctx.registerSecret(value);
      out.push(npmrcTokenFinding(path, i + 1, `${m[1]}=${redactSecret(value)}`));
    });
  }
  for (const issue of packageConfigIssues(basename(path), text)) out.push(packageConfigFinding(path, issue));
  return out;
}

async function scanWorkflow(path: string, ctx: ScanContext): Promise<Finding[]> {
  const text = await ctx.files.read(path);
  return text === null ? [] : workflowIssues(text).map((issue) => workflowFinding(path, issue));
}

function mcpFindings(path: string, text: string, ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  for (const server of readMcpServers(text)) {
    const at = Math.max(text.indexOf(JSON.stringify(server.name)), 0);
    const line = lineOf(text, at);
    const launch = unpinnedLauncher(server);
    if (launch) out.push(unpinnedMcpFinding(path, line, server, launch));
    for (const { name, value } of literalSecretEnv(server)) {
      ctx.registerSecret(value);
      const envAt = text.indexOf(JSON.stringify(name), at);
      out.push(mcpSecretFinding(path, lineOf(text, envAt < 0 ? at : envAt), server, name, redactSecret(value)));
    }
  }
  return out;
}

async function scanAgentConfig(path: string, ctx: ScanContext): Promise<Finding[]> {
  if (ctx.files.isIgnored(path)) return [];
  const text = await ctx.files.read(path);
  if (text === null) return [];
  const out: Finding[] = [];
  const hidden = findHiddenText(text);
  if (hidden) out.push(hiddenTextFinding(path, hidden));
  if (isMcpConfigPath(path)) out.push(...mcpFindings(path, text, ctx));
  return out;
}

export const agent: Agent = {
  id: "supply-chain",
  name: "SupplyChain",
  role: "Flags typosquats, slopsquats, vulnerable framework versions, risky CI workflows and agent-config backdoors",
  modes: ["static"],
  async run(ctx) {
    const paths = ctx.files.paths.filter((p) => !inNodeModules(p));
    const out: Finding[] = [];

    const manifests: Manifest[] = [];
    for (const file of paths.filter((p) => basename(p) === "package.json")) {
      const raw = await ctx.files.read(file);
      if (raw === null || raw.length > MAX_FILE_BYTES_HINT) continue;
      const m = parseManifest(file, raw);
      if (m) manifests.push(m);
      else out.push(unreadableFinding(file));
    }

    const state: ScanState = {
      locks: new LockResolver(ctx),
      workspaceNames: new Set(manifests.flatMap((m) => (m.name ? [m.name] : []))),
      reportedRisky: new Set<string>(),
      resolved: new Map(),
    };
    for (const m of manifests) out.push(...(await scanManifest(m, state)));
    for (const lockPath of state.locks.present) {
      const info = await state.locks.get(lockPath);
      if (info) out.push(...scanLockfile(info, state));
    }
    out.push(...(await scanAdvisories(state, ctx, paths)));

    for (const p of paths.filter((x) => PACKAGE_CONFIG_FILES.has(basename(x)))) out.push(...(await scanPackageConfig(p, ctx)));
    for (const p of paths.filter(isWorkflowPath)) out.push(...(await scanWorkflow(p, ctx)));
    for (const p of paths.filter(isAgentConfigPath)) out.push(...(await scanAgentConfig(p, ctx)));
    return out;
  },
};
