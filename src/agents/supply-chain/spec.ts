import { posix } from "node:path";

export type SpecIssueKind = "git" | "tarball" | "github-shorthand" | "file-outside" | "wildcard";

export interface SpecIssue {
  readonly kind: SpecIssueKind;
  readonly detail: string;
}

const WILDCARDS = new Set(["", "*", "latest", "x", "X"]);
const PINNED_COMMIT = /#[0-9a-f]{7,40}$/i;
const HOSTED_PREFIX = /^(?:github|gitlab|bitbucket|gist):/;
const SHORTHAND = /^[\w.-]+\/[\w.-]+(?:#.+)?$/;
const SAFE_PROTOCOL = /^(?:workspace|npm|catalog|jsr):/;
const ABSOLUTE = /^(?:[\\/]|[a-zA-Z]:|~)/;

function fileIssue(spec: string, pkgDir: string): SpecIssue | null {
  const rest = spec.replace(/^(?:file|link):/, "").replace(/^\/\/(?=\/)/, "");
  if (ABSOLUTE.test(rest)) return { kind: "file-outside", detail: "absolute path outside the repository" };
  const resolved = posix.normalize(posix.join(pkgDir, rest));
  return resolved === ".." || resolved.startsWith("../")
    ? { kind: "file-outside", detail: "path escapes the repository" }
    : null;
}

/** Classifies a dependency version specifier; null means it is an ordinary registry range. */
export function classifySpec(spec: string, pkgDir: string): SpecIssue | null {
  const s = spec.trim();
  if (WILDCARDS.has(s)) return { kind: "wildcard", detail: `"${s || "(empty)"}" accepts any version, including a malicious new release` };
  if (SAFE_PROTOCOL.test(s)) return null;
  if (/^(?:file|link):/.test(s)) return fileIssue(s, pkgDir);
  if (/^git:\/\//.test(s)) return { kind: "git", detail: "unauthenticated git:// protocol" };
  if (/^(?:git\+\w+:\/\/|git@)/.test(s) || (/^https?:\/\/.+\.git(?:#.*)?$/.test(s))) {
    return PINNED_COMMIT.test(s) ? null : { kind: "git", detail: "git dependency not pinned to a commit hash" };
  }
  if (/^https?:\/\//.test(s)) return { kind: "tarball", detail: "remote tarball, contents can change without a version bump" };
  if (HOSTED_PREFIX.test(s) || SHORTHAND.test(s)) {
    return PINNED_COMMIT.test(s) ? null : { kind: "github-shorthand", detail: "git shorthand not pinned to a commit hash" };
  }
  return null;
}

export interface DistTagIssue {
  readonly tag: string;
  readonly severity: "low" | "medium";
}

/** Moving tags that publish untested or nightly builds are riskier than release-candidate style tags. */
const DIST_TAGS: ReadonlyMap<string, "low" | "medium"> = new Map([
  ["canary", "medium"], ["experimental", "medium"], ["alpha", "medium"],
  ["beta", "low"], ["rc", "low"], ["next", "low"],
]);

/** A dependency whose whole spec is an unstable dist-tag ("canary", "beta", ...); null otherwise. */
export function distTagIssue(spec: string): DistTagIssue | null {
  const tag = spec.trim().toLowerCase();
  const severity = DIST_TAGS.get(tag);
  return severity ? { tag, severity } : null;
}

export interface SourceSpec {
  readonly kind: "git" | "tarball" | "github-shorthand";
  /** Git sources only: pinned to a commit hash. */
  readonly pinned: boolean;
}

/**
 * Where a non-registry spec points, regardless of pinning. Used for overrides, where even a
 * commit-pinned git source replaces a registry package with code outside the registry.
 */
export function sourceSpec(spec: string): SourceSpec | null {
  const s = spec.trim();
  if (SAFE_PROTOCOL.test(s) || /^(?:file|link):/.test(s)) return null;
  if (/^git:\/\//.test(s) || /^(?:git\+\w+:\/\/|git@)/.test(s) || /^https?:\/\/.+\.git(?:#.*)?$/.test(s)) {
    return { kind: "git", pinned: PINNED_COMMIT.test(s) };
  }
  if (/^https?:\/\//.test(s)) return { kind: "tarball", pinned: false };
  if (HOSTED_PREFIX.test(s) || SHORTHAND.test(s)) return { kind: "github-shorthand", pinned: PINNED_COMMIT.test(s) };
  return null;
}
