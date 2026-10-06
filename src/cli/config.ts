import { promises as fs } from "node:fs";
import path from "node:path";
import { isSeverity } from "../core/severity.js";
import type { RuleOverride, Severity } from "../core/types.js";
import { UsageError } from "./args.js";

export const CONFIG_FILE = "whsquad.config.json";

const MAX_CONFIG_BYTES = 1_000_000;
const MAX_IGNORE_PATHS = 500;
/** Matches the glob matcher's own cap: longer globs would be silently ignored. */
const MAX_GLOB_LENGTH = 256;
const KNOWN_KEYS = new Set(["failOn", "ignorePaths", "rules", "baseline"]);
const RULE_KEY = /^[A-Z][A-Z0-9]*-[A-Z0-9]*\*?$/;

export interface ParsedConfig {
  readonly failOn?: Severity;
  readonly ignorePaths: readonly string[];
  readonly rules: Readonly<Record<string, RuleOverride>>;
  readonly baseline?: string;
}

export interface LoadedConfig extends ParsedConfig {
  /** Path of the file as found on disk. */
  readonly source: string;
  /** `baseline` resolved against the config file's directory. */
  readonly baselinePath?: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validates the config shape; every failure is a UsageError that names the file. */
export function parseConfig(text: string, source: string): ParsedConfig {
  const fail = (msg: string): never => {
    throw new UsageError(`${source}: ${msg}`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return fail(`not valid JSON (${e instanceof Error ? e.message : String(e)}).`);
  }
  if (!isPlainObject(raw)) return fail("must be a JSON object.");
  for (const key of Object.keys(raw)) {
    if (!KNOWN_KEYS.has(key)) fail(`unknown setting "${key}". Known settings: ${[...KNOWN_KEYS].join(", ")}.`);
  }

  let failOn: Severity | undefined;
  if (raw["failOn"] !== undefined) {
    const v = raw["failOn"];
    if (typeof v !== "string" || !isSeverity(v)) fail('"failOn" must be one of critical, high, medium, low, info.');
    failOn = v as Severity;
  }

  const ignorePaths: string[] = [];
  if (raw["ignorePaths"] !== undefined) {
    const v = raw["ignorePaths"];
    if (!Array.isArray(v)) fail('"ignorePaths" must be an array of glob strings.');
    if ((v as unknown[]).length > MAX_IGNORE_PATHS) fail(`"ignorePaths" has more than ${MAX_IGNORE_PATHS} entries.`);
    for (const entry of v as unknown[]) {
      if (typeof entry !== "string" || entry.trim() === "") fail('"ignorePaths" entries must be non-empty strings.');
      if ((entry as string).length > MAX_GLOB_LENGTH) fail(`"ignorePaths" entries must be at most ${MAX_GLOB_LENGTH} characters.`);
      ignorePaths.push(entry as string);
    }
  }

  const rules: Record<string, RuleOverride> = {};
  if (raw["rules"] !== undefined) {
    const v = raw["rules"];
    if (!isPlainObject(v)) fail('"rules" must be an object of rule id (or prefix like "DB-*") to "off" or a severity.');
    for (const [key, value] of Object.entries(v as Record<string, unknown>)) {
      const id = key.toUpperCase();
      if (!RULE_KEY.test(id)) fail(`"rules" key "${key}" is not a rule id (SEC-090) or prefix wildcard (DB-*).`);
      if (typeof value !== "string" || (value !== "off" && !isSeverity(value))) {
        fail(`"rules.${key}" must be "off" or one of critical, high, medium, low, info.`);
      }
      rules[id] = value as RuleOverride;
    }
  }

  if (raw["baseline"] !== undefined && (typeof raw["baseline"] !== "string" || raw["baseline"] === "")) {
    fail('"baseline" must be a file path string.');
  }

  return {
    ...(failOn ? { failOn } : {}),
    ignorePaths,
    rules,
    ...(typeof raw["baseline"] === "string" ? { baseline: raw["baseline"] } : {}),
  };
}

/** Reads `whsquad.config.json` from `dir`; null when absent. */
export async function loadConfig(dir: string): Promise<LoadedConfig | null> {
  const file = path.join(dir, CONFIG_FILE);
  let text: string;
  try {
    const stat = await fs.stat(file);
    if (!stat.isFile()) return null;
    if (stat.size > MAX_CONFIG_BYTES) throw new UsageError(`${file}: larger than ${MAX_CONFIG_BYTES} bytes.`);
    text = await fs.readFile(file, "utf8");
  } catch (e) {
    if (e instanceof UsageError) throw e;
    return null;
  }
  const parsed = parseConfig(text, file);
  return {
    ...parsed,
    source: file,
    ...(parsed.baseline ? { baselinePath: path.resolve(dir, parsed.baseline) } : {}),
  };
}
