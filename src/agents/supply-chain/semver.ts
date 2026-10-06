/**
 * Minimal semver helpers (no dependencies). Ranges use GitHub's advisory syntax:
 * comma-separated comparators, e.g. ">= 13.0.0, < 13.5.9" or "= 19.2.0". Prereleases are ordered
 * per the semver spec and are NOT excluded from ranges, which is how the advisory database reads them.
 */

export interface ParsedVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly pre: readonly string[];
}

const VERSION_RE = /^[=v]*(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
const COMPARATOR_RE = /^(>=|<=|>|<|=)?\s*(\S+)$/;

export function parseVersion(input: string): ParsedVersion | null {
  const m = VERSION_RE.exec(input.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    pre: m[4] ? m[4].split(".") : [],
  };
}

function comparePreIdentifier(a: string, b: string): number {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) return Math.sign(Number(a) - Number(b));
  if (aNum) return -1; // numeric identifiers sort below alphanumeric ones
  if (bNum) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function comparePre(a: readonly string[], b: readonly string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // a release outranks its prereleases
  if (b.length === 0) return -1;
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i++) {
    const c = comparePreIdentifier(a[i] ?? "", b[i] ?? "");
    if (c !== 0) return c;
  }
  return Math.sign(a.length - b.length);
}

function compareParsed(a: ParsedVersion, b: ParsedVersion): number {
  return (
    Math.sign(a.major - b.major) ||
    Math.sign(a.minor - b.minor) ||
    Math.sign(a.patch - b.patch) ||
    comparePre(a.pre, b.pre)
  );
}

/** Negative, zero or positive like a sort comparator; null when either side is not a full version. */
export function compareVersions(a: string, b: string): number | null {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  return pa && pb ? compareParsed(pa, pb) : null;
}

function holds(op: string, cmp: number): boolean {
  switch (op) {
    case ">=": return cmp >= 0;
    case "<=": return cmp <= 0;
    case ">": return cmp > 0;
    case "<": return cmp < 0;
    default: return cmp === 0;
  }
}

/** True when `version` satisfies every comparator in `range`. Malformed input is simply false. */
export function satisfies(version: string, range: string): boolean {
  const v = parseVersion(version);
  if (!v) return false;
  const parts = range.split(",").map((p) => p.trim());
  if (parts.length === 0 || parts.some((p) => p === "")) return false;
  for (const part of parts) {
    const m = COMPARATOR_RE.exec(part);
    const bound = m?.[2] ? parseVersion(m[2]) : null;
    if (!m || !bound) return false;
    if (!holds(m[1] ?? "=", compareParsed(v, bound))) return false;
  }
  return true;
}

const EXACT_RE = /^[=v]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

/** The version a manifest spec pins exactly ("1.2.3", "=1.2.3", "v1.2.3"); null for ranges, tags and aliases. */
export function exactVersion(spec: string): string | null {
  return EXACT_RE.exec(spec.trim())?.[1] ?? null;
}
