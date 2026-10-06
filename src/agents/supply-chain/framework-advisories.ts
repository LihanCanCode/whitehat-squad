import { makeFinding } from "../../core/finding.js";
import type { Evidence, Finding, ScanContext, Severity, Confidence } from "../../core/types.js";
import { ADVISORY_SNAPSHOT_DATE, advisoriesFor, type FrameworkAdvisory } from "../../data/advisories.js";
import { compareVersions, parseVersion, satisfies } from "./semver.js";

export interface MiddlewareFile {
  readonly file: string;
  readonly callsAuth: boolean;
}

/** Facts about the repo that decide whether an advisory is reachable. */
export interface RepoSignals {
  readonly hasAppDir: boolean;
  readonly middleware: readonly MiddlewareFile[];
}

export interface MatchedAdvisory {
  readonly advisory: FrameworkAdvisory;
  /** First patched version for the range that matched. */
  readonly patched: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
}

const APP_DIR_FILE = /(?:^|\/)app\/(?:.+\/)?(?:page|layout|route|loading|error|not-found|template|default|global-error)\.(?:tsx?|jsx?|mjs|mdx)$/;
const MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.(?:tsx?|jsx?|mjs|cjs|mts|cts)$/;
const AUTH_CALL =
  /\bauth(?:enticate\w*|orize\w*|Middleware)?\s*\(|\b(?:getToken|getSession|getServerSession|withAuth|clerkMiddleware|jwtVerify|verifyToken|updateSession|createServerClient)\s*\(|\bsupabase\.auth\b|\bNextAuth\s*\(|from\s+['"](?:next-auth|@clerk\/|@auth\/|@supabase\/ssr)/;

export async function collectSignals(ctx: ScanContext, paths: readonly string[]): Promise<RepoSignals> {
  const middleware: MiddlewareFile[] = [];
  for (const file of paths.filter((p) => MIDDLEWARE_FILE.test(p))) {
    const text = await ctx.files.read(file);
    middleware.push({ file, callsAuth: text !== null && AUTH_CALL.test(text) });
  }
  return { hasAppDir: paths.some((p) => APP_DIR_FILE.test(p)), middleware };
}

function requirementMet(a: FrameworkAdvisory, signals: RepoSignals): boolean {
  if (a.requires === "app-dir") return signals.hasAppDir;
  if (a.requires === "middleware") return signals.middleware.length > 0;
  return true;
}

function assess(a: FrameworkAdvisory, signals: RepoSignals): { severity: Severity; confidence: Confidence } {
  if (a.category === "dos") return { severity: "medium", confidence: "medium" };
  if (a.escalateWithMiddlewareAuth) {
    if (signals.middleware.some((m) => m.callsAuth)) return { severity: "critical", confidence: "high" };
    if (signals.middleware.length > 0) return { severity: "high", confidence: "medium" };
    return { severity: "medium", confidence: "low" };
  }
  return { severity: a.severity, confidence: a.conditional ? "medium" : "high" };
}

export function matchAdvisories(pkg: string, version: string, signals: RepoSignals): MatchedAdvisory[] {
  const out: MatchedAdvisory[] = [];
  for (const advisory of advisoriesFor(pkg)) {
    const range = advisory.ranges.find((r) => satisfies(version, r.range));
    if (!range || !requirementMet(advisory, signals)) continue;
    out.push({ advisory, patched: range.patched, ...assess(advisory, signals) });
  }
  return out;
}

/**
 * Lowest version that clears every advisory matching `version`: repeatedly jump to the highest
 * patched version until nothing matches. Prereleases are only recommended for prerelease installs.
 */
export function recommendedFix(pkg: string, version: string, matches: readonly MatchedAdvisory[], signals: RepoSignals): string | undefined {
  const allowPre = (parseVersion(version)?.pre.length ?? 0) > 0;
  let current = matches;
  let best: string | undefined;
  for (let i = 0; i < 12 && current.length > 0; i++) {
    const candidates = current
      .map((m) => m.patched)
      .filter((v) => allowPre || (parseVersion(v)?.pre.length ?? 0) === 0);
    const top = candidates.reduce<string | undefined>((a, v) => (a === undefined || (compareVersions(v, a) ?? 0) > 0 ? v : a), undefined);
    if (top === undefined) return best;
    best = top;
    current = matchAdvisories(pkg, top, signals);
  }
  return current.length === 0 ? best : undefined;
}

const REF_GHSA = "https://github.com/advisories/";

function middlewareNote(m: MatchedAdvisory, signals: RepoSignals): string {
  if (!m.advisory.escalateWithMiddlewareAuth) return "";
  const withAuth = signals.middleware.find((x) => x.callsAuth);
  if (withAuth) return ` Your ${withAuth.file} performs authorization, which is exactly what this bug lets attackers skip, so this is critical for you.`;
  if (signals.middleware.length > 0) return ` Your ${signals.middleware[0]?.file} does not obviously call auth, so the impact depends on what it protects.`;
  return " No middleware or proxy file was found, so nothing is known to be bypassable; upgrade anyway.";
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = { high: 2, medium: 1, low: 0 };

/** Most serious first: severity, then confidence; denial-of-service advisories last. */
function byImpact(a: MatchedAdvisory, b: MatchedAdvisory): number {
  const dos = Number(a.advisory.category === "dos") - Number(b.advisory.category === "dos");
  return dos || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
}

const label = (m: MatchedAdvisory): string => m.advisory.cve ?? m.advisory.ghsa;
const fullLabel = (m: MatchedAdvisory): string => (m.advisory.cve ? `${m.advisory.cve} (${m.advisory.ghsa})` : m.advisory.ghsa);
const majorOf = (v: string): number | undefined => parseVersion(v)?.major;

const maxVersion = (versions: readonly string[]): string | undefined =>
  versions.reduce<string | undefined>((a, v) => (a === undefined || (compareVersions(v, a) ?? 0) > 0 ? v : a), undefined);

interface UpgradePlan {
  /** Version the fix command installs. */
  readonly target: string;
  /** Advisories still matching `target` (fixed only on a newer major line). */
  readonly remaining: readonly MatchedAdvisory[];
  /** Lowest release clearing everything, when it differs from target. */
  readonly clearsAll?: string;
}

/**
 * Prefer a patch on the installed major line (no breaking upgrade, like Dependabot); name the
 * major upgrade separately when some advisories are only fixed there.
 */
function planUpgrade(pkg: string, version: string, matches: readonly MatchedAdvisory[], best: string | undefined, signals: RepoSignals): UpgradePlan {
  const major = majorOf(version);
  const sameLine = maxVersion(matches.map((m) => m.patched).filter((v) => majorOf(v) === major));
  const target = sameLine ?? best ?? (maxVersion(matches.map((m) => m.patched)) as string);
  const remaining = matchAdvisories(pkg, target, signals);
  return { target, remaining, ...(best && best !== target ? { clearsAll: best } : {}) };
}

/**
 * One finding per vulnerable name@version. An old framework version is usually hit by many
 * advisories at once; one card per advisory buried the single action that matters ("upgrade to X"),
 * so the finding is ranked by its most serious advisory and lists the rest in the explanation.
 */
export function groupFinding(
  evidence: Evidence, pkg: string, version: string, matches: readonly MatchedAdvisory[], best: string | undefined, signals: RepoSignals,
): Finding {
  const ordered = [...matches].sort(byImpact);
  const top = ordered[0] as MatchedAdvisory;
  const others = ordered.slice(1).filter((m) => m.advisory.category !== "dos");
  const dos = ordered.filter((m) => m !== top && m.advisory.category === "dos");
  const plan = planUpgrade(pkg, version, matches, best, signals);
  const target = plan.target;
  const install = `npm install ${pkg}@${target}`;
  const count = matches.length;
  const a = top.advisory;
  const topId = fullLabel(top);
  const also = others.length > 0 ? ` Also affected by: ${others.map((m) => `${fullLabel(m)} (${m.severity}): ${m.advisory.summary}`).join("; ")}.` : "";
  const dosNote = dos.length > 0
    ? ` Plus ${dos.length} denial-of-service advisor${dos.length === 1 ? "y" : "ies"} (${dos.map(fullLabel).join(", ")}) that let a remote client crash or exhaust the server.`
    : "";
  const fixed = count - plan.remaining.length;
  const majorNote = plan.remaining.length > 0
    ? ` ${plan.remaining.length} more (${plan.remaining.map(label).join(", ")}) are only fixed on a newer major line` +
      `${plan.clearsAll ? ` (${pkg}@${plan.clearsAll} clears everything)` : ""} — plan that upgrade with the ${pkg} migration guide.`
    : "";
  const clears = plan.remaining.length === 0
    ? `clears all ${count} advisor${count === 1 ? "y" : "ies"} without a major-version upgrade`
    : `clears ${fixed} of ${count} without a major-version upgrade.${majorNote}`;
  return makeFinding({
    ruleId: "SUP-010",
    agentId: "supply-chain",
    title: count === 1
      ? `${pkg}@${version} is affected by ${label(top)}: ${a.summary}`
      : `${pkg}@${version} has ${count} known security advisories, including ${label(top)}: ${a.summary}`,
    severity: top.severity,
    confidence: top.confidence,
    explanation:
      `${pkg}@${version} falls inside the affected range of ${count === 1 ? "a published advisory" : `${count} published advisories`}. ` +
      `Most serious: ${topId} — ${a.summary}, fixed in ${pkg}@${top.patched}.` +
      `${a.conditional ? ` Exploitation depends on a condition we cannot see: ${a.conditional}.` : ""}${middlewareNote(top, signals)}` +
      `${also}${dosNote} (Advisory data snapshot ${ADVISORY_SNAPSHOT_DATE}.)`,
    evidence: [evidence],
    fix: {
      summary: `Upgrade ${pkg} to ${target}: ${install} — ${clears}`.replace(/\.?$/, "."),
      config: install,
      agentPrompt:
        `${pkg}@${version} has ${count} known security advisor${count === 1 ? "y" : "ies"}, the most serious being ${topId}. ` +
        `Run \`${install}\`, regenerate the lockfile, run the build and tests, and confirm with \`npm ls ${pkg}\` that only ${target} or later remains.`,
      references: ordered.map((m) => `${REF_GHSA}${m.advisory.ghsa}`),
    },
    target: evidence.file ?? "package.json",
    cwe: "CWE-1395",
  });
}

/** The SUP-010 finding (at most one) for one resolved name@version. */
export function findingsForVersion(evidence: Evidence, pkg: string, version: string, signals: RepoSignals): Finding[] {
  const matches = matchAdvisories(pkg, version, signals);
  if (matches.length === 0) return [];
  return [groupFinding(evidence, pkg, version, matches, recommendedFix(pkg, version, matches, signals), signals)];
}
