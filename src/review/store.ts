import { createHash } from "node:crypto";
import { promises as fs, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { SEVERITIES } from "./prompts.js";
import type { CachedUnit, LedgerEntry, ReviewCache, ReviewResult } from "./pipeline.js";
import { REVIEW_CLASS_IDS } from "./rules.meta.js";
import type { Finding } from "../core/types.js";
import { assertSafeTarget } from "../safety/safe-write.js";

/**
 * Review state (cache, last review, per-run sandbox) lives in a PER-USER folder outside every scanned
 * repo. A repo can therefore never plant cached "no findings" results or fake AI findings, and the
 * sandbox Claude Code runs in never sits under the repo (it reads CLAUDE.md from every parent folder).
 */
export class StateError extends Error {}

const CACHE_VERSION = 2;
const MAX_ENTRIES = 2000;

function realOrResolved(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return path.resolve(p);
  }
}

function isInside(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (rel.split(path.sep)[0] !== ".." && !path.isAbsolute(rel));
}

export interface ReviewPaths {
  readonly stateDir: string;
  readonly cacheFile: string;
  readonly lastReviewFile: string;
  readonly sandboxRoot: string;
}

/** Paths for one project, keyed by the real path of its root. Throws if the state folder is inside it. */
export function reviewPaths(root: string, env: NodeJS.ProcessEnv = process.env): ReviewPaths {
  const stateDir = path.resolve(env["WHSQUAD_STATE_DIR"] || path.join(os.homedir(), ".whsquad", "review"));
  const realRoot = realOrResolved(root);
  if (isInside(realOrResolved(stateDir), realRoot) || isInside(stateDir, path.resolve(root))) {
    throw new StateError(`The review state folder (${stateDir}) is inside the scanned project; set WHSQUAD_STATE_DIR to a folder outside it.`);
  }
  const project = createHash("sha256").update(realRoot.toLowerCase()).digest("hex").slice(0, 16);
  return {
    stateDir,
    cacheFile: path.join(stateDir, "cache", `${project}.json`),
    lastReviewFile: path.join(stateDir, "reviews", `${project}.json`),
    sandboxRoot: path.join(stateDir, "sandbox"),
  };
}

/** Creates the state folder privately (0700) and, on POSIX, refuses one owned by another user. */
export async function ensureStateDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const st = await fs.lstat(dir);
  if (st.isSymbolicLink()) throw new StateError(`${dir} is a symbolic link; refusing to use it for review state.`);
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new StateError(`${dir} belongs to another user; refusing to use it for review state.`);
  }
}

/** A fresh, empty, private folder for one run of `claude` (removed afterwards). */
export async function makeSandbox(paths: ReviewPaths): Promise<string> {
  await ensureStateDir(paths.stateDir);
  await fs.mkdir(paths.sandboxRoot, { recursive: true, mode: 0o700 });
  return fs.mkdtemp(path.join(paths.sandboxRoot, "run-"));
}

const isStr = (v: unknown, max = 5000): v is string => typeof v === "string" && v.length <= max;

/** Strict shape check: anything unexpected is discarded rather than rendered or trusted. */
export function isAiFinding(v: unknown): v is Finding {
  if (typeof v !== "object" || v === null) return false;
  const f = v as Record<string, unknown>;
  const fix = f["fix"] as Record<string, unknown> | undefined;
  const verify = f["verify"] as Record<string, unknown> | undefined;
  return f["origin"] === "ai" &&
    isStr(f["id"], 40) && /^[\w-]+$/.test(f["id"] as string) &&
    REVIEW_CLASS_IDS.includes(f["ruleId"] as string) &&
    isStr(f["title"], 300) && isStr(f["explanation"]) &&
    ([...SEVERITIES, "info"] as string[]).includes(f["severity"] as string) &&
    ["medium", "low"].includes(f["confidence"] as string) &&
    (f["reviewState"] === "confirmed" || f["reviewState"] === "needs_validation") &&
    Array.isArray(f["evidence"]) && (f["evidence"] as unknown[]).length <= 4 &&
    (f["evidence"] as unknown[]).every((e) => typeof e === "object" && e !== null && isStr((e as { snippet?: unknown }).snippet, 400)) &&
    typeof fix === "object" && fix !== null && isStr(fix["summary"]) && isStr(fix["agentPrompt"], 2000) &&
    typeof verify === "object" && verify !== null && isStr(verify["command"], 600);
}

function isEntry(v: unknown): v is LedgerEntry {
  return typeof v === "object" && v !== null && isStr((v as LedgerEntry).unit, 600) && typeof (v as LedgerEntry).confirmed === "number";
}

/** File-backed per-user cache. Corrupt or foreign files are ignored (a fresh review is always safe). */
export class FileReviewCache implements ReviewCache {
  private entries = new Map<string, CachedUnit>();
  private dirty = false;

  constructor(private readonly paths: ReviewPaths) {}

  async load(): Promise<void> {
    try {
      const doc = JSON.parse(await fs.readFile(this.paths.cacheFile, "utf8")) as { version?: number; entries?: Record<string, CachedUnit> };
      if (doc.version !== CACHE_VERSION || typeof doc.entries !== "object" || doc.entries === null) return;
      for (const [k, v] of Object.entries(doc.entries)) {
        if (v && v.key === k && Array.isArray(v.findings) && v.findings.every(isAiFinding) && isEntry(v.entry)) this.entries.set(k, v);
      }
    } catch {
      /* no cache yet */
    }
  }

  get(key: string): CachedUnit | undefined {
    return this.entries.get(key);
  }

  set(value: CachedUnit): void {
    this.entries.set(value.key, value);
    this.dirty = true;
  }

  async save(): Promise<void> {
    if (!this.dirty) return;
    await ensureStateDir(this.paths.stateDir);
    await assertSafeTarget(this.paths.stateDir, this.paths.cacheFile);
    await fs.mkdir(path.dirname(this.paths.cacheFile), { recursive: true, mode: 0o700 });
    const entries = Object.fromEntries([...this.entries].slice(-MAX_ENTRIES));
    await fs.writeFile(this.paths.cacheFile, JSON.stringify({ version: CACHE_VERSION, entries }), { encoding: "utf8", mode: 0o600 });
  }
}

/** The last review, kept so `review --recheck <id>` can re-validate one finding after a fix. */
export interface StoredReview {
  readonly version: 2;
  readonly target: string;
  readonly result: ReviewResult;
}

export async function saveLastReview(paths: ReviewPaths, target: string, result: ReviewResult): Promise<void> {
  await ensureStateDir(paths.stateDir);
  await assertSafeTarget(paths.stateDir, paths.lastReviewFile);
  await fs.mkdir(path.dirname(paths.lastReviewFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(paths.lastReviewFile, JSON.stringify({ version: 2, target, result } satisfies StoredReview), { encoding: "utf8", mode: 0o600 });
}

export async function loadLastReview(paths: ReviewPaths): Promise<StoredReview | null> {
  try {
    const doc = JSON.parse(await fs.readFile(paths.lastReviewFile, "utf8")) as StoredReview;
    return doc.version === 2 && Array.isArray(doc.result?.findings) && doc.result.findings.every(isAiFinding) ? doc : null;
  } catch {
    return null;
  }
}
