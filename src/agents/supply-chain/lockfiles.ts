import { parseJsonc } from "./jsonc.js";

export type LockKind = "npm" | "pnpm" | "yarn" | "bun";

export interface LockEntry {
  readonly name: string;
  readonly version: string;
  readonly hasResolved: boolean;
  readonly hasIntegrity: boolean;
  readonly hasInstallScript: boolean;
}

export interface LockInfo {
  readonly file: string;
  readonly kind: LockKind;
  readonly entries: readonly LockEntry[];
  readonly byName: ReadonlyMap<string, readonly LockEntry[]>;
}

export const LOCKFILE_NAMES: readonly { readonly file: string; readonly kind: LockKind }[] = [
  { file: "package-lock.json", kind: "npm" },
  { file: "npm-shrinkwrap.json", kind: "npm" },
  { file: "pnpm-lock.yaml", kind: "pnpm" },
  { file: "yarn.lock", kind: "yarn" },
  { file: "bun.lock", kind: "bun" },
  { file: "bun.lockb", kind: "bun" },
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function npmEntry(name: string, raw: Record<string, unknown>): LockEntry | null {
  const version = str(raw["version"]);
  const resolved = str(raw["resolved"]);
  if (!version || raw["link"] === true || resolved?.startsWith("file:")) return null;
  return {
    name,
    version,
    hasResolved: resolved !== undefined,
    hasIntegrity: str(raw["integrity"]) !== undefined,
    hasInstallScript: raw["hasInstallScript"] === true,
  };
}

function walkNpmV1(deps: Record<string, unknown>, out: LockEntry[]): void {
  for (const [name, raw] of Object.entries(deps)) {
    if (!isRecord(raw)) continue;
    const entry = npmEntry(name, raw);
    if (entry) out.push(entry);
    if (isRecord(raw["dependencies"])) walkNpmV1(raw["dependencies"], out);
  }
}

function parseNpm(text: string): LockEntry[] {
  const json: unknown = JSON.parse(text);
  const out: LockEntry[] = [];
  if (!isRecord(json)) return out;
  const packages = json["packages"];
  if (isRecord(packages)) {
    const marker = "node_modules/";
    for (const [key, raw] of Object.entries(packages)) {
      const at = key.lastIndexOf(marker);
      if (at < 0 || !isRecord(raw)) continue; // "" root and workspace folders
      const entry = npmEntry(str(raw["name"]) ?? key.slice(at + marker.length), raw);
      if (entry) out.push(entry);
    }
  } else if (isRecord(json["dependencies"])) {
    walkNpmV1(json["dependencies"], out);
  }
  return out;
}

const PNPM_AT = /^(@[^/]+\/[^@]+|[^@/][^@]*)@(\d[^()\s]*)/;
const PNPM_SLASH = /^(@[^/]+\/[^/]+|[^/]+)\/(\d[^/_()]*)/;

function pnpmKey(rawKey: string): { name: string; version: string } | null {
  const key = rawKey.replace(/:$/, "").replace(/^['"]|['"]$/g, "").replace(/^\//, "");
  const m = PNPM_AT.exec(key) ?? PNPM_SLASH.exec(key);
  return m?.[1] && m[2] ? { name: m[1], version: m[2] } : null;
}

function parsePnpm(text: string): LockEntry[] {
  const out: LockEntry[] = [];
  let inPackages = false;
  let cur: { name: string; version: string; resolved: boolean; integrity: boolean; script: boolean } | null = null;
  const flush = (): void => {
    if (cur) out.push({ name: cur.name, version: cur.version, hasResolved: cur.resolved, hasIntegrity: cur.integrity, hasInstallScript: cur.script });
    cur = null;
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      flush();
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    if (/^ {2}\S/.test(line)) {
      flush();
      const parsed = pnpmKey(line.trim());
      cur = parsed ? { ...parsed, resolved: false, integrity: false, script: false } : null;
    } else if (cur) {
      if (/\bresolution:/.test(line)) cur.resolved = true;
      if (/\bintegrity:/.test(line)) cur.integrity = true;
      if (/\brequiresBuild:\s*true/.test(line)) cur.script = true;
    }
  }
  flush();
  return out;
}

function yarnName(header: string): string | null {
  const first = (header.replace(/:$/, "").split(",")[0] ?? "").trim().replace(/^"|"$/g, "");
  const at = first.indexOf("@", 1);
  return at > 0 ? first.slice(0, at) : null;
}

function parseYarn(text: string): LockEntry[] {
  const out: LockEntry[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const lines = block.split(/\r?\n/).filter((l) => l.trim() !== "" && !l.startsWith("#"));
    const header = lines[0];
    if (!header || /^\s/.test(header) || !header.endsWith(":") || header.startsWith("__metadata")) continue;
    const name = yarnName(header);
    const version = /^[ \t]+version:?[ \t]+"?([^"\s]+)"?/m.exec(block)?.[1];
    if (!name || !version) continue;
    out.push({
      name,
      version,
      hasResolved: /^[ \t]+(?:resolved|resolution):?\s/m.test(block),
      hasIntegrity: /^[ \t]+(?:integrity|checksum):?\s/m.test(block),
      hasInstallScript: false,
    });
  }
  return out;
}

const BUN_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

/** "name@1.2.3", "@scope/name@1.2.3" or "alias@npm:real@1.2.3"; null for workspace, git, file and tarball idents. */
function bunIdent(ident: string): { name: string; version: string } | null {
  const alias = ident.indexOf("@npm:", 1);
  if (alias > 0) return bunIdent(ident.slice(alias + 5));
  const at = ident.lastIndexOf("@");
  if (at <= 0) return null;
  const version = ident.slice(at + 1);
  return BUN_VERSION.test(version) ? { name: ident.slice(0, at), version } : null;
}

/** Text bun.lock is JSONC: comments and trailing commas are allowed. Each package is [ident, registry, meta, integrity]. */
function parseBun(text: string): LockEntry[] {
  const json = parseJsonc(text);
  const packages = isRecord(json) ? json["packages"] : undefined;
  if (!isRecord(packages)) throw new Error("bun.lock has no packages table");
  const out: LockEntry[] = [];
  for (const raw of Object.values(packages)) {
    if (!Array.isArray(raw) || typeof raw[0] !== "string") continue;
    const parsed = bunIdent(raw[0]);
    if (!parsed) continue;
    const integrity = raw[3];
    out.push({
      ...parsed,
      hasResolved: typeof raw[1] === "string",
      hasIntegrity: typeof integrity === "string" && /^sha\d+-/.test(integrity),
      hasInstallScript: false,
    });
  }
  return out;
}

/** Parses a lockfile into a flat entry list. Throws on malformed npm JSON or bun.lock; callers handle it. */
export function parseLockfile(file: string, kind: LockKind, text: string): LockInfo {
  const entries = kind === "npm" ? parseNpm(text) : kind === "pnpm" ? parsePnpm(text) : kind === "yarn" ? parseYarn(text) : parseBun(text);
  const byName = new Map<string, LockEntry[]>();
  for (const e of entries) byName.set(e.name, [...(byName.get(e.name) ?? []), e]);
  return { file, kind, entries, byName };
}
