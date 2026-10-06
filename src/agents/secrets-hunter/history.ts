import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { findSecrets, isSkippedPath, type RawMatch } from "./scanner.js";

const MAX_COMMITS = 500;
const MAX_BYTES = 20 * 1024 * 1024;
const GIT_TIMEOUT_MS = 60_000;
const MAX_HITS = 50;
const COMMIT_MARK = "@@whsq-commit ";
const BYTES_PER_MB = 1024 * 1024;

export interface HistoryHit {
  readonly match: RawMatch;
  readonly file: string;
  readonly line: number;
  readonly commit: string;
}

export interface HistoryLimits {
  /** Stop reading git's output after this many bytes. */
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly maxCommits: number;
}

const DEFAULT_LIMITS: HistoryLimits = { maxBytes: MAX_BYTES, timeoutMs: GIT_TIMEOUT_MS, maxCommits: MAX_COMMITS };

interface RemovedLine {
  readonly no: number;
  readonly text: string;
}

/**
 * Absolute path to git taken from PATH only. The scanned repo is untrusted: on Windows a bare
 * "git" would be resolved against the child's cwd first, so a repo shipping git.exe would run it.
 */
export function resolveGit(root: string, pathEnv = process.env.PATH ?? ""): string | null {
  const names = process.platform === "win32" ? ["git.exe", "git.cmd"] : ["git"];
  const untrusted = path.resolve(root);
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const resolved = path.resolve(dir);
    if (resolved === untrusted || resolved.startsWith(untrusted + path.sep)) continue;
    for (const name of names) {
      const candidate = path.join(resolved, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function warn(message: string): void {
  process.stderr.write(`Warning: ${message}\n`);
}

/** Hardened git arguments: no pager, no fsmonitor, no external diff or textconv drivers from repo config. */
export function gitLogArgs(root: string, maxCommits: number): string[] {
  return [
    "-C", root,
    "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
    "log", "-p", `--max-count=${maxCommits}`, "--no-color", "--no-ext-diff", "--no-textconv",
    `--format=${COMMIT_MARK}%H`,
  ];
}

type StopReason = "bytes" | "time";

interface GitLogRead {
  readonly text: string;
  readonly bytes: number;
  readonly stoppedBy: StopReason | null;
}

/**
 * Streams `git log -p` and keeps everything read before a limit is hit, instead of discarding the
 * whole output on overflow. Resolves null when git cannot run or fails (not a repo, bad root).
 */
function readGitLog(git: string, root: string, limits: HistoryLimits): Promise<GitLogRead | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let stoppedBy: StopReason | null = null;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const settle = (value: GitLogRead | null): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };

    let child: ChildProcess;
    try {
      child = spawn(git, gitLogArgs(root, limits.maxCommits), {
        // Not the scanned repo: nothing in it can be picked up as a relative executable.
        cwd: os.tmpdir(),
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
        windowsHide: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      settle(null);
      return;
    }

    const stop = (reason: StopReason): void => {
      if (stoppedBy) return;
      stoppedBy = reason;
      child.kill();
    };
    timer = setTimeout(() => stop("time"), limits.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stoppedBy) return;
      const room = limits.maxBytes - bytes;
      if (chunk.length > room) {
        chunks.push(chunk.subarray(0, room));
        bytes += room;
        stop("bytes");
        return;
      }
      chunks.push(chunk);
      bytes += chunk.length;
    });
    child.on("error", () => settle(null));
    child.on("close", (code) => {
      if (!stoppedBy && code !== 0) return settle(null);
      let text = Buffer.concat(chunks).toString("utf8");
      // A limit can cut a line in half; never parse a partial last line.
      if (stoppedBy) text = text.slice(0, text.lastIndexOf("\n") + 1);
      settle({ text, bytes, stoppedBy });
    });
  });
}

const OCTAL_ESCAPE = /^[0-7]{1,3}/;
const SIMPLE_ESCAPES: Readonly<Record<string, number>> = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '"': 34, "\\": 92 };

/** Decodes git's C-style quoted path ("a/caf\303\251.ts"); unquoted paths just lose git's trailing tab. */
export function unquoteGitPath(raw: string): string {
  const value = raw.replace(/\t+$/, "");
  if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"')) return value;
  const inner = value.slice(1, -1);
  const bytes: number[] = [];
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i] ?? "";
    if (ch !== "\\") {
      bytes.push(...Buffer.from(String.fromCodePoint(inner.codePointAt(i) ?? 63)));
      if ((inner.codePointAt(i) ?? 0) > 0xffff) i++;
      continue;
    }
    const octal = OCTAL_ESCAPE.exec(inner.slice(i + 1, i + 4))?.[0];
    if (octal) {
      bytes.push(parseInt(octal, 8) & 0xff);
      i += octal.length;
      continue;
    }
    const next = inner[i + 1] ?? "";
    bytes.push(SIMPLE_ESCAPES[next] ?? next.charCodeAt(0));
    i++;
  }
  return Buffer.from(bytes).toString("utf8");
}

function pathFromHeader(header: string): string | null {
  if (header.trim() === "/dev/null") return null;
  return unquoteGitPath(header).replace(/^[ab]\//, "");
}

interface ParsedHistory {
  readonly hits: HistoryHit[];
  readonly commits: number;
}

function parseHistory(log: string, currentValues: ReadonlySet<string>): ParsedHistory {
  const hits: HistoryHit[] = [];
  const seen = new Set<string>();
  let commits = 0;
  let commit = "";
  let file: string | null = null;
  let oldFile: string | null = null;
  let inHunk = false;
  let oldLine = 0;
  let removed: RemovedLine[] = [];

  const flush = (): void => {
    if (file && removed.length > 0 && !isSkippedPath(file)) {
      const text = removed.map((r) => r.text).join("\n");
      for (const match of findSecrets(text, file, { generic: false })) {
        if (currentValues.has(match.value) || seen.has(match.value) || hits.length >= MAX_HITS) continue;
        seen.add(match.value);
        const no = removed[match.line - 1]?.no ?? 1;
        hits.push({ match, file, line: no, commit: commit.slice(0, 8) });
      }
    }
    removed = [];
  };

  for (const line of log.split("\n")) {
    if (line.startsWith(COMMIT_MARK)) {
      flush();
      commits++;
      commit = line.slice(COMMIT_MARK.length).trim();
      file = null;
      inHunk = false;
    } else if (line.startsWith("diff --git ")) {
      flush();
      file = null;
      oldFile = null;
      inHunk = false;
    } else if (!inHunk && line.startsWith("--- ")) {
      oldFile = pathFromHeader(line.slice(4));
    } else if (!inHunk && line.startsWith("+++ ")) {
      file = pathFromHeader(line.slice(4)) ?? oldFile;
    } else if (line.startsWith("@@ ")) {
      inHunk = true;
      oldLine = Number(/^@@ -(\d+)/.exec(line)?.[1] ?? 1);
    } else if (inHunk && line.startsWith("-")) {
      removed.push({ no: oldLine++, text: line.slice(1) });
    } else if (inHunk && line.startsWith(" ")) {
      oldLine++;
    }
  }
  flush();
  return { hits, commits };
}

const megabytes = (bytes: number): string => `${(bytes / BYTES_PER_MB).toFixed(2)} MB`;
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

function warnIfStopped(read: GitLogRead, commits: number, limits: HistoryLimits): void {
  const progress = `stopped after ${plural(commits, "commit")} / ${megabytes(read.bytes)}`;
  if (read.stoppedBy === "bytes") {
    warn(`git history scan ${progress} (size limit of ${megabytes(limits.maxBytes)} reached); older commits were not checked.`);
  } else if (read.stoppedBy === "time") {
    warn(`git history scan ${progress} (${Math.round(limits.timeoutMs / 1000)} s time limit reached); older commits were not checked.`);
  } else if (commits >= limits.maxCommits) {
    warn(`git history scan covered the most recent ${plural(commits, "commit")}; older commits were not checked.`);
  }
}

/** Secrets in lines removed by past commits that are not still present in the working tree. */
export async function scanGitHistory(
  root: string,
  currentValues: ReadonlySet<string>,
  overrides: Partial<HistoryLimits> = {},
): Promise<HistoryHit[]> {
  const git = resolveGit(root);
  if (!git) return [];
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  const read = await readGitLog(git, root, limits);
  if (!read) {
    return [];
  }
  const { hits, commits } = parseHistory(read.text, currentValues);
  warnIfStopped(read, commits, limits);
  return hits;
}
