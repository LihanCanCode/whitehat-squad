import { promises as fs } from "node:fs";
import path from "node:path";
import type { FileIndex, FileStats } from "./types.js";

export const MAX_FILES = 20_000;
export const MAX_FILE_BYTES = 1_000_000;

/** Directories never walked. The file watcher derives its ignore list from this, so they cannot drift. */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", ".temp", ".tmp",
  ".turbo", ".vercel", ".cache", "coverage", ".venv", "venv", "__pycache__", ".whsquad",
]);
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar",
  ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".mov", ".wasm", ".exe", ".dll", ".so", ".bin",
]);

// .gitignore comes from the (untrusted) scanned repo, as do the paths it is matched against, so
// globs are matched with a bounded dynamic-programming matcher instead of a generated RegExp,
// which could backtrack exponentially on a pattern like "*a*a*a*a*b".
const MAX_GLOB_LENGTH = 256;
const MAX_MATCH_TEXT = 1024;

type GlobToken =
  | { readonly kind: "lit"; readonly char: string }
  | { readonly kind: "star" } // "*": any run of non-slash characters
  | { readonly kind: "glob" } // "**": any run of characters
  | { readonly kind: "any" }; // "?": one non-slash character

function tokenizeGlob(glob: string): GlobToken[] | null {
  if (glob.length > MAX_GLOB_LENGTH) return null;
  const tokens: GlobToken[] = [];
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") {
      if (glob[i + 1] === "*") { tokens.push({ kind: "glob" }); i++; } else tokens.push({ kind: "star" });
    } else if (c === "?") tokens.push({ kind: "any" });
    else tokens.push({ kind: "lit", char: c });
  }
  return tokens;
}

/** O(tokens x text) full-string match. */
export function globMatch(tokens: readonly GlobToken[], text: string): boolean {
  if (text.length > MAX_MATCH_TEXT) return false;
  const n = text.length;
  let prev = new Array<boolean>(n + 1).fill(false);
  prev[0] = true;
  for (const token of tokens) {
    const next = new Array<boolean>(n + 1).fill(false);
    if (token.kind === "star" || token.kind === "glob") {
      next[0] = prev[0] as boolean;
      for (let j = 1; j <= n; j++) {
        const crossable = token.kind === "glob" || text[j - 1] !== "/";
        next[j] = (prev[j] as boolean) || ((next[j - 1] as boolean) && crossable);
      }
    } else {
      for (let j = 0; j < n; j++) {
        const ch = text[j] as string;
        const ok = token.kind === "any" ? ch !== "/" : ch === token.char;
        next[j + 1] = (prev[j] as boolean) && ok;
      }
    }
    prev = next;
  }
  return prev[n] as boolean;
}

/** Minimal .gitignore matcher: comments, negation, trailing "/", anchored and floating patterns. */
export function buildIgnoreMatcher(gitignore: string): (relPath: string) => boolean {
  const rules = gitignore
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((raw) => {
      const negate = raw.startsWith("!");
      let pattern = negate ? raw.slice(1) : raw;
      const dirOnly = pattern.endsWith("/");
      if (dirOnly) pattern = pattern.slice(0, -1);
      const anchored = pattern.startsWith("/") || pattern.slice(0, -1).includes("/");
      if (pattern.startsWith("/")) pattern = pattern.slice(1);
      return { negate, dirOnly, anchored, tokens: tokenizeGlob(pattern) };
    })
    .filter((rule): rule is typeof rule & { tokens: GlobToken[] } => rule.tokens !== null);

  return (relPath: string): boolean => {
    const segments = relPath.split("/");
    let ignored = false;
    for (const rule of rules) {
      let matched = false;
      for (let i = 0; i < segments.length && !matched; i++) {
        const isLast = i === segments.length - 1;
        if (rule.dirOnly && isLast) continue;
        const candidate = rule.anchored ? segments.slice(0, i + 1).join("/") : (segments[i] as string);
        matched = globMatch(rule.tokens, candidate);
      }
      if (matched) ignored = !rule.negate;
    }
    return ignored;
  };
}

interface WalkCounters {
  skippedBinaryExt: number;
}

async function walk(root: string, dir: string, out: string[], counters: WalkCounters): Promise<void> {
  if (out.length >= MAX_FILES) return;
  let entries;
  try {
    entries = await fs.readdir(path.join(root, dir), { withFileTypes: true });
  } catch {
    return;
  }
  // Plain code-unit order, not localeCompare: the file order must not depend on the machine locale.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  // Installed third-party Python (a virtualenv, or `pip install --target dir`) is not the project's code.
  if (dir !== "" && entries.some((e) => (e.isDirectory() && e.name.endsWith(".dist-info")) || (e.isFile() && e.name === "pyvenv.cfg"))) return;
  for (const entry of entries) {
    if (out.length >= MAX_FILES) return;
    const rel = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await walk(root, rel, out, counters);
    } else if (entry.isFile()) {
      if (BINARY_EXT.has(path.extname(entry.name).toLowerCase())) counters.skippedBinaryExt += 1;
      else out.push(rel);
    }
  }
}

export async function indexDirectory(root: string): Promise<FileIndex> {
  const absRoot = path.resolve(root);
  const paths: string[] = [];
  const counters: WalkCounters = { skippedBinaryExt: 0 };
  await walk(absRoot, "", paths, counters);
  let readOk = 0;
  let skippedLarge = 0;
  let skippedBinaryContent = 0;

  let gitignore = "";
  try {
    gitignore = await fs.readFile(path.join(absRoot, ".gitignore"), "utf8");
  } catch {
    /* no .gitignore is a valid state */
  }
  const isIgnored = buildIgnoreMatcher(gitignore);
  const known = new Set(paths);
  const cache = new Map<string, string | null>();

  return {
    paths,
    truncated: paths.length >= MAX_FILES,
    isIgnored,
    stats: (): FileStats => ({
      read: readOk,
      skippedLarge,
      skippedBinary: counters.skippedBinaryExt + skippedBinaryContent,
    }),
    async read(relPath: string): Promise<string | null> {
      if (!known.has(relPath)) return null;
      if (cache.has(relPath)) return cache.get(relPath) ?? null;
      let text: string | null = null;
      try {
        const full = path.join(absRoot, relPath);
        const stat = await fs.stat(full);
        if (stat.size <= MAX_FILE_BYTES) {
          const raw = await fs.readFile(full);
          if (raw.includes(0)) skippedBinaryContent += 1;
          else {
            text = raw.toString("utf8");
            readOk += 1;
          }
        } else {
          skippedLarge += 1;
        }
      } catch {
        text = null;
      }
      cache.set(relPath, text);
      return text;
    },
  };
}
