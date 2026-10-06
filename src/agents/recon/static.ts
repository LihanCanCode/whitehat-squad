import type { BackendName, FileIndex, FrameworkName } from "../../core/types.js";
import { extractBackendHints, type BackendHints } from "./hints.js";

export interface StaticSignals {
  readonly frameworks: ReadonlySet<FrameworkName>;
  readonly backends: ReadonlySet<BackendName>;
  readonly hints: BackendHints;
}

const MAX_SOURCE_FILES = 400;
const SOURCE_EXT_RE = /\.(?:[cm]?[jt]sx?|html|vue|svelte)$/;
const IMPORT_RES: ReadonlyArray<readonly [BackendName, RegExp]> = [
  ["stripe", /(?:from|require\(|import\()\s*["']stripe["']/],
  ["openai", /(?:from|require\(|import\()\s*["']openai["']/],
  ["anthropic", /(?:from|require\(|import\()\s*["']@anthropic-ai\/sdk["']/],
];

const basename = (p: string): string => p.slice(p.lastIndexOf("/") + 1);
const isEnvFile = (p: string): boolean => basename(p).startsWith(".env");
const inNodeModules = (p: string): boolean => p.startsWith("node_modules/") || p.includes("/node_modules/");

function depNames(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
    const obj = parsed as Record<string, unknown>;
    const names: string[] = [];
    for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
      const section = obj[key];
      if (section && typeof section === "object") names.push(...Object.keys(section));
    }
    return names;
  } catch {
    return [];
  }
}

function applyDeps(names: readonly string[], fw: Set<FrameworkName>, be: Set<BackendName>): void {
  for (const n of names) {
    if (n === "next") fw.add("next");
    else if (n === "react") fw.add("react");
    else if (n === "express") fw.add("express");
    else if (n.startsWith("@remix-run/")) fw.add("remix");
    else if (n === "@supabase/supabase-js") be.add("supabase");
    else if (n === "firebase" || n === "firebase-admin") be.add("firebase");
    else if (n === "stripe" || n === "@stripe/stripe-js") be.add("stripe");
    else if (n === "openai") be.add("openai");
    else if (n === "@anthropic-ai/sdk") be.add("anthropic");
  }
}

function applyPaths(paths: readonly string[], fw: Set<FrameworkName>, be: Set<BackendName>): void {
  for (const p of paths) {
    const b = basename(p);
    if (/^next\.config\./.test(b)) fw.add("next");
    if (/^vite\.config\./.test(b)) fw.add("vite");
    if (p.startsWith("supabase/") || p.includes("/supabase/")) be.add("supabase");
    if (b === "firebase.json" || b === "firestore.rules" || b === ".firebaserc") be.add("firebase");
  }
}

function firebaseRcProject(text: string): string | undefined {
  try {
    const parsed = JSON.parse(text) as { projects?: Record<string, unknown> };
    const projects = parsed.projects ?? {};
    const id = projects["default"] ?? Object.values(projects)[0];
    return typeof id === "string" && id ? id : undefined;
  } catch {
    return undefined;
  }
}

async function safeRead(files: FileIndex, p: string): Promise<string | null> {
  try {
    return await files.read(p);
  } catch {
    return null;
  }
}

/** Reads manifests, env files and a bounded number of source files. Never throws. */
export async function scanStatic(files: FileIndex): Promise<StaticSignals> {
  const frameworks = new Set<FrameworkName>();
  const backends = new Set<BackendName>();
  const hints: BackendHints = {};
  try {
    const paths = files.paths.filter((p) => !inNodeModules(p));
    applyPaths(paths, frameworks, backends);
    const sources: string[] = [];
    for (const p of paths) {
      const b = basename(p);
      if (b === "package.json") {
        const text = await safeRead(files, p);
        if (text) applyDeps(depNames(text), frameworks, backends);
      } else if (b === ".firebaserc") {
        const id = firebaseRcProject((await safeRead(files, p)) ?? "");
        if (id && !hints.firebaseProjectId) hints.firebaseProjectId = id;
      } else if (isEnvFile(p) || SOURCE_EXT_RE.test(b)) {
        sources.push(p);
      }
    }
    // env files first so they win over incidental matches in code
    sources.sort((a, c) => Number(isEnvFile(c)) - Number(isEnvFile(a)));
    let sourceCount = 0;
    for (const p of sources) {
      const isEnv = isEnvFile(p);
      if (!isEnv && ++sourceCount > MAX_SOURCE_FILES) break;
      const text = await safeRead(files, p);
      if (!text) continue;
      const h = extractBackendHints(text);
      if (h.supabaseUrl && !hints.supabaseUrl) hints.supabaseUrl = h.supabaseUrl;
      if (h.anonKey && !hints.anonKey) hints.anonKey = h.anonKey;
      if (h.firebaseProjectId && !hints.firebaseProjectId) hints.firebaseProjectId = h.firebaseProjectId;
      if (/NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL/.test(text)) backends.add("supabase");
      if (!isEnv) for (const [name, re] of IMPORT_RES) if (re.test(text)) backends.add(name);
    }
  } catch {
    /* keep whatever was collected */
  }
  if (hints.supabaseUrl) backends.add("supabase");
  if (hints.firebaseProjectId) backends.add("firebase");
  return { frameworks, backends, hints };
}
