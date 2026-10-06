import { lineOf } from "../../core/finding.js";

export const DEP_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
/** Hooks that run for everyone who installs or checks out the project. */
export const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepublish"] as const;
/** Hooks that run when the maintainer packs or publishes. */
export const PUBLISH_HOOKS = ["prepublishOnly", "prepack", "postpack"] as const;

export type DepSection = (typeof DEP_SECTIONS)[number] | "bundledDependencies";
export type OverrideSource = "overrides" | "resolutions" | "pnpm.overrides";

export interface Dep {
  readonly name: string;
  readonly spec: string;
  readonly section: DepSection;
  readonly line: number;
  /** The raw source line, trimmed. */
  readonly text: string;
}

export interface OverrideEntry {
  readonly name: string;
  readonly spec: string;
  readonly source: OverrideSource;
  readonly line: number;
  readonly text: string;
}

export interface ScriptEntry {
  readonly hook: string;
  readonly command: string;
  readonly line: number;
  /** "install" hooks run for every installer; "publish" hooks only for the maintainer. */
  readonly when: "install" | "publish";
}

export interface Manifest {
  readonly file: string;
  /** Directory relative to the repo root; "" for the root. */
  readonly dir: string;
  readonly name?: string;
  readonly deps: readonly Dep[];
  readonly scripts: readonly ScriptEntry[];
  readonly overrides: readonly OverrideEntry[];
  readonly raw: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/** 1-based line of `"key":` in the raw text, searching from `from` when given; 1 if not found. */
export function findKeyLine(raw: string, key: string, from = 0): number {
  const m = new RegExp(`"${escapeRe(key)}"\\s*:`).exec(raw.slice(from));
  return m ? lineOf(raw, from + m.index) : 1;
}

function sectionOffset(raw: string, section: string): number {
  const m = new RegExp(`"${section}"\\s*:`).exec(raw);
  return m ? m.index : 0;
}

export function dirOf(file: string): string {
  const i = file.lastIndexOf("/");
  return i < 0 ? "" : file.slice(0, i);
}

function stringLine(raw: string, value: string, from: number): number {
  const at = raw.indexOf(JSON.stringify(value), from);
  return at < 0 ? 1 : lineOf(raw, at);
}

/** Flattens npm-style nested overrides ({ foo: { ".": "1.0.0", bar: "2.0.0" } }) into name/spec pairs. */
function flattenOverrides(block: Record<string, unknown>, parent: string | null, out: { name: string; spec: string }[]): void {
  for (const [key, value] of Object.entries(block)) {
    const name = key === "." && parent ? parent : key;
    if (typeof value === "string") out.push({ name, spec: value });
    else if (isRecord(value)) flattenOverrides(value, key === "." ? parent : key, out);
  }
}

function readOverrides(json: Record<string, unknown>, raw: string, lines: readonly string[]): OverrideEntry[] {
  const pnpm = isRecord(json["pnpm"]) ? json["pnpm"] : undefined;
  const blocks: { source: OverrideSource; block: unknown; base: number }[] = [
    { source: "overrides", block: json["overrides"], base: sectionOffset(raw, "overrides") },
    { source: "resolutions", block: json["resolutions"], base: sectionOffset(raw, "resolutions") },
    { source: "pnpm.overrides", block: pnpm?.["overrides"], base: sectionOffset(raw, "pnpm") },
  ];
  const out: OverrideEntry[] = [];
  for (const { source, block, base } of blocks) {
    if (!isRecord(block)) continue;
    const flat: { name: string; spec: string }[] = [];
    flattenOverrides(block, null, flat);
    for (const { name, spec } of flat) {
      const line = stringLine(raw, spec, base);
      out.push({ name, spec, source, line, text: (lines[line - 1] ?? "").trim() });
    }
  }
  return out;
}

function readDeps(json: Record<string, unknown>, raw: string, lines: readonly string[]): Dep[] {
  const deps: Dep[] = [];
  const seen = new Set<string>();
  for (const section of DEP_SECTIONS) {
    const block = json[section];
    if (!isRecord(block)) continue;
    const base = sectionOffset(raw, section);
    for (const [name, spec] of Object.entries(block)) {
      if (typeof spec !== "string" || seen.has(name)) continue;
      seen.add(name);
      const line = findKeyLine(raw, name, base);
      deps.push({ name, spec, section, line, text: (lines[line - 1] ?? "").trim() });
    }
  }
  // bundledDependencies only lists names (the specs live in dependencies); keep names that are not declared elsewhere.
  for (const key of ["bundledDependencies", "bundleDependencies"]) {
    const list = json[key];
    if (!Array.isArray(list)) continue;
    const base = sectionOffset(raw, key);
    for (const name of list) {
      if (typeof name !== "string" || seen.has(name)) continue;
      seen.add(name);
      const line = stringLine(raw, name, base);
      deps.push({ name, spec: "", section: "bundledDependencies", line, text: (lines[line - 1] ?? "").trim() });
    }
  }
  return deps;
}

function readScripts(json: Record<string, unknown>, raw: string): ScriptEntry[] {
  const rawScripts = json["scripts"];
  if (!isRecord(rawScripts)) return [];
  const base = sectionOffset(raw, "scripts");
  const out: ScriptEntry[] = [];
  const groups = [{ hooks: INSTALL_HOOKS, when: "install" }, { hooks: PUBLISH_HOOKS, when: "publish" }] as const;
  for (const { hooks, when } of groups) {
    for (const hook of hooks) {
      const command = rawScripts[hook];
      if (typeof command === "string") out.push({ hook, command, line: findKeyLine(raw, hook, base), when });
    }
  }
  return out;
}

/** Parses package.json text. Returns null when the JSON is invalid or not an object. */
export function parseManifest(file: string, raw: string): Manifest | null {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(json)) return null;

  const lines = raw.split(/\r?\n/);
  const name = typeof json["name"] === "string" ? json["name"] : undefined;
  return {
    file,
    dir: dirOf(file),
    ...(name ? { name } : {}),
    deps: readDeps(json, raw, lines),
    scripts: readScripts(json, raw),
    overrides: readOverrides(json, raw, lines),
    raw,
  };
}
