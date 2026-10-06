import { promises as fs } from "node:fs";
import path from "node:path";
import { indexDirectory } from "../core/fs-walk.js";
import { runScan } from "../core/orchestrator.js";
import type { ScanPolicy } from "../core/policy.js";
import type { FileIndex, PersistedScanOptions, SafeHttpClient, ScanReport } from "../core/types.js";
import { createSafeHttpClient } from "../safety/http-client.js";
import { verifyOwnership } from "../safety/ownership.js";
import { assertSafeTarget } from "../safety/safe-write.js";
import type { CliOptions } from "./args.js";
import { loadBaselineIds } from "./baseline.js";
import { loadConfig } from "./config.js";

export const STATE_DIR = ".whsquad";
export const LAST_REPORT = "last-report.json";

export class OwnershipError extends Error {}
export class TargetError extends Error {}

const NO_FILES: FileIndex = { paths: [], read: async () => null, isIgnored: () => false };

export function isUrlTarget(target: string): boolean {
  return /^https?:\/\//i.test(target);
}

export interface ScanExtras {
  /** Shell flavour for printed verify commands; defaults to the host platform (injectable for tests). */
  readonly platform?: NodeJS.Platform;
  /** `whsquad baseline` must record everything, so it scans without applying any existing baseline. */
  readonly ignoreBaseline?: boolean;
}

/** Wraps a client so the coverage block can report how many requests the scan sent. */
export function withRequestCounter(http: SafeHttpClient): { readonly client: SafeHttpClient; readonly count: () => number } {
  let n = 0;
  return {
    count: () => n,
    client: {
      get: (url, opts) => {
        n += 1;
        return http.get(url, opts);
      },
      head: (url, opts) => {
        n += 1;
        return http.head(url, opts);
      },
    },
  };
}

function persistedOptions(options: CliOptions): PersistedScanOptions {
  return { gitHistory: options.gitHistory, probeDatabase: options.probeDatabase, allowPrivate: options.allowPrivate };
}

/** Flags that change what a scan does; repeated in printed verify commands so a re-check is like-for-like. */
function verifyFlags(options: CliOptions, live: boolean): string[] {
  return live
    ? [...(options.probeDatabase ? ["--probe-database"] : []), ...(options.allowPrivate ? ["--allow-private"] : [])]
    : [...(options.gitHistory ? ["--git-history"] : [])];
}

/** Config file (scan root for static, cwd for live) + CLI filters + baseline, merged. CLI wins. */
async function buildPolicy(configDir: string, options: CliOptions, extras: ScanExtras): Promise<ScanPolicy> {
  const config = options.noConfig ? null : await loadConfig(configDir);
  const baselinePath = options.baseline ?? config?.baselinePath;
  const baselineLabel = options.baseline ?? config?.baseline;
  const baselineIds = baselinePath && !extras.ignoreBaseline ? await loadBaselineIds(baselinePath) : undefined;
  return {
    ...(config ? { source: config.source } : {}),
    ...(config?.failOn ? { failOn: config.failOn } : {}),
    ignorePaths: config?.ignorePaths ?? [],
    rules: config?.rules ?? {},
    only: options.only,
    exclude: options.exclude,
    ...(baselineLabel && !extras.ignoreBaseline ? { baseline: baselineLabel } : {}),
    ...(baselineIds ? { baselineIds } : {}),
  };
}

/** Runs a static scan of a directory or a read-only live scan of an owned site. */
export async function scanTarget(
  target: string,
  options: CliOptions,
  stateDir = process.cwd(),
  extras: ScanExtras = {},
): Promise<ScanReport> {
  const report = isUrlTarget(target)
    ? await scanLive(target, options, stateDir, extras)
    : await scanStatic(target, options, extras);
  return { ...report, scanOptions: persistedOptions(options) };
}

async function scanStatic(target: string, options: CliOptions, extras: ScanExtras): Promise<ScanReport> {
  const root = path.resolve(target);
  const stat = await fs.stat(root).catch(() => null);
  if (!stat?.isDirectory()) throw new TargetError(`"${target}" is not a directory or an http(s) URL.`);
  const policy = await buildPolicy(root, options, extras);
  const files = await indexDirectory(root);
  if (files.truncated) {
    process.stderr.write(`Warning: more than ${files.paths.length} files; only the first ${files.paths.length} were scanned.
`);
  }
  return runScan({
    mode: "static",
    targetLabel: target,
    root,
    files,
    options: { gitHistory: options.gitHistory },
    policy,
    verifyFlags: verifyFlags(options, false),
    ...(extras.platform ? { platform: extras.platform } : {}),
  });
}

async function scanLive(target: string, options: CliOptions, stateDir: string, extras: ScanExtras): Promise<ScanReport> {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new TargetError(`"${target}" is not a valid URL.`);
  }
  const policy = await buildPolicy(stateDir, options, extras);
  const ownership = await verifyOwnership(url, {
    dir: path.join(stateDir, STATE_DIR),
    allowPrivate: options.allowPrivate,
  });
  if (!ownership.verified) {
    throw new OwnershipError(
      `Ownership of ${url.hostname} is not verified (${ownership.detail}).
` +
        `Run "whsquad init-proof ${url.hostname}", publish the token, then scan again.`,
    );
  }
  const counted = withRequestCounter(
    createSafeHttpClient({
      origin: url,
      allowPrivate: options.allowPrivate,
      allowBackendHosts: options.probeDatabase,
      maxRequests: options.maxRequests,
    }),
  );
  return runScan({
    mode: "live",
    targetLabel: target,
    files: NO_FILES,
    target: url,
    http: counted.client,
    options: { probeBackend: options.probeDatabase, maxRequests: options.maxRequests },
    policy,
    requestCount: counted.count,
    verifyFlags: verifyFlags(options, true),
    ...(extras.platform ? { platform: extras.platform } : {}),
  });
}

export async function saveLastReport(report: ScanReport, stateDir = process.cwd()): Promise<void> {
  const dir = path.join(stateDir, STATE_DIR);
  await assertSafeTarget(stateDir, path.join(dir, LAST_REPORT));
  // The report lists exploitable holes: keep it private to the current user (best effort on Windows).
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(dir, LAST_REPORT), JSON.stringify(report), { encoding: "utf8", mode: 0o600 });
}

export async function loadLastReport(stateDir = process.cwd()): Promise<ScanReport | null> {
  try {
    const raw = await fs.readFile(path.join(stateDir, STATE_DIR, LAST_REPORT), "utf8");
    const parsed: unknown = JSON.parse(raw);
    return isScanReport(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isScanReport(value: unknown): value is ScanReport {
  return (
    typeof value === "object" && value !== null &&
    (value as { tool?: unknown }).tool === "whitehat-squad" &&
    Array.isArray((value as { findings?: unknown }).findings)
  );
}
