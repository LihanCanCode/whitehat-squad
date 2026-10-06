import { profileStack } from "../agents/recon/index.js";
import { scrubText } from "../safety/redact.js";
import { DETERMINISTIC_RULES } from "../rules/catalog.js";
import { applyPolicy, type ScanPolicy } from "./policy.js";
import { SEVERITY_ORDER } from "./severity.js";
import { SQUAD } from "./registry.js";
import { applySuppressions } from "./suppress.js";
import type {
  Agent, Coverage, Evidence, FileIndex, Finding, Mode, SafeHttpClient, ScanContext, ScanOptions, ScanReport,
  SuppressedFinding,
} from "./types.js";

export const VERSION = "0.3.0";

export interface ScanInput {
  readonly mode: Mode;
  readonly targetLabel: string;
  readonly files: FileIndex;
  readonly root?: string;
  readonly target?: URL;
  readonly http?: SafeHttpClient;
  readonly options?: Partial<ScanOptions>;
  readonly agents?: readonly Agent[];
  /** Config file + CLI filters. Omit for a plain scan. */
  readonly policy?: ScanPolicy;
  /** Live scans: how many HTTP requests were sent so far (reported in coverage). */
  readonly requestCount?: () => number;
  /** Scan flags (e.g. "--git-history") repeated in each finding's printed verify command. */
  readonly verifyFlags?: readonly string[];
  /** Shell flavour for quoting the printed verify command; defaults to the host platform. */
  readonly platform?: NodeJS.Platform;
}

const DEFAULT_OPTIONS: ScanOptions = { gitHistory: false, maxRequests: 100 };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Anything outside this set in a path could act as shell syntax or as a prompt line when an agent
// pastes it into a command or into text the user hands to a coding agent.
const UNSAFE_PATH_CHAR = /[^\p{L}\p{M}\p{N}_@%+=:,./\\ \[\]()-]/gu;

/** File names come from the scanned repo (untrusted). Neutralise shell and prompt-injection characters. */
export function safePath(file: string): string {
  return file.replace(UNSAFE_PATH_CHAR, "_");
}

function scrubEvidence(evidence: readonly Evidence[], s: (t: string) => string): Evidence[] {
  return evidence.map((e) => ({
    ...e,
    ...(e.file ? { file: s(e.file) } : {}),
    ...(e.url ? { url: s(e.url) } : {}),
    snippet: s(e.snippet),
  }));
}

function scrubFinding(f: Finding, secrets: ReadonlySet<string>): Finding {
  const unsafeFiles = [...new Set(f.evidence.flatMap((e) => (e.file && safePath(e.file) !== e.file ? [e.file] : [])))];
  const s = (t: string): string => {
    let out = scrubText(t, secrets);
    for (const file of unsafeFiles) out = out.split(file).join(safePath(file));
    return out;
  };
  return {
    ...f,
    title: s(f.title),
    explanation: s(f.explanation),
    evidence: scrubEvidence(f.evidence, s),
    fix: {
      ...f.fix,
      summary: s(f.fix.summary),
      agentPrompt: s(f.fix.agentPrompt),
      ...(f.fix.sql ? { sql: s(f.fix.sql) } : {}),
      ...(f.fix.config ? { config: s(f.fix.config) } : {}),
      ...(f.fix.patch ? { patch: { file: s(f.fix.patch.file), diff: s(f.fix.patch.diff) } } : {}),
    },
  };
}

/**
 * Quote a CLI argument so paths with spaces or metacharacters survive copy-paste: single quotes on
 * POSIX shells, double quotes on Windows (cmd.exe and PowerShell both accept "..." with \" inside).
 * `platform` is injectable so both forms are testable on any host.
 */
export function shellQuote(arg: string, platform: NodeJS.Platform = process.platform): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg;
  if (platform === "win32") return `"${arg.replace(/"/g, '\\"')}"`;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

const TEST_PATH = /(^|[\\/])(tests?|__tests__|__mocks__|fixtures?|spec|e2e)[\\/]|\.(test|spec)\.[cm]?[jt]sx?$/i;

/**
 * Deliberately-vulnerable fixtures and test data are not real exposure. Agents treat test paths
 * differently from each other, so the squad applies one rule: demote to low confidence (still
 * shown, but it never fails a build on its own).
 */
function demoteTestPaths(f: Finding): Finding {
  const files = f.evidence.flatMap((e) => (e.file ? [e.file] : []));
  const allInTests = files.length > 0 && files.length === f.evidence.length && files.every((p) => TEST_PATH.test(p));
  return allInTests && f.confidence !== "low" ? { ...f, confidence: "low" } : f;
}

/** Agents may carry absolute paths; the report always shows the target as the user typed it. */
function withVerifyCommand(f: Finding, input: ScanInput): Finding {
  const flags = (input.verifyFlags ?? []).map((flag) => ` ${flag}`).join("");
  const target = shellQuote(input.targetLabel, input.platform);
  return {
    ...f,
    verify: { command: `whsquad verify ${f.ruleId} ${target}${flags}`, ruleId: f.ruleId, target: input.targetLabel },
  };
}

/** Code-unit order: identical on every machine, unlike localeCompare. */
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || cmp(a.ruleId, b.ruleId) || cmp(a.id, b.id),
  );
}

const evidenceKey = (e: Evidence): string => `${e.file ?? ""}:${e.line ?? ""}:${e.url ?? ""}`;

/** Appends `extra` evidence to `base`, skipping entries already present (by file:line:url). */
function mergeEvidence(base: readonly Evidence[], extra: readonly Evidence[]): Evidence[] {
  const seen = new Set(base.map(evidenceKey));
  const merged = [...base];
  for (const e of extra) {
    if (seen.has(evidenceKey(e))) continue;
    seen.add(evidenceKey(e));
    merged.push(e);
  }
  return merged;
}

/**
 * Rule pairs that can flag the same code: at a shared file:line only the owner (value) is kept.
 * Runs after suppression and policy, so a filtered-out owner never takes the other finding with it.
 */
const OVERLAPS: ReadonlyMap<string, string> = new Map([["WEB-006", "INJ-007"]]);

/** Only exact file:line locations can overlap; evidence without a line never matches. */
const locKey = (e: Evidence): string | undefined => (e.file && e.line !== undefined ? `${e.file}:${e.line}` : undefined);

/** Drops evidence of an overlapping rule where its owner already reports the same location; empty findings go. */
function dropOverlaps(findings: readonly Finding[]): Finding[] {
  const owned = new Map<string, Set<string>>();
  for (const f of findings) {
    if (![...OVERLAPS.values()].includes(f.ruleId)) continue;
    const locs = owned.get(f.ruleId) ?? new Set<string>();
    for (const e of f.evidence) {
      const key = locKey(e);
      if (key) locs.add(key);
    }
    owned.set(f.ruleId, locs);
  }
  return findings.flatMap((f) => {
    const owner = OVERLAPS.get(f.ruleId);
    const taken = owner ? owned.get(owner) : undefined;
    if (!taken) return [f];
    const evidence = f.evidence.filter((e) => {
      const key = locKey(e);
      return !key || !taken.has(key);
    });
    if (evidence.length === f.evidence.length) return [f];
    return evidence.length === 0 ? [] : [{ ...f, evidence }];
  });
}

/**
 * Same id => same finding reported twice: merge the evidence. Same id at a different line of the
 * same snippet is a distinct occurrence and gets its own `id~line` entry (also merged on repeat).
 */
function dedupe(findings: readonly Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const f of findings) {
    const line = f.evidence[0]?.line;
    const first = unique.get(f.id);
    const key = !first || first.evidence[0]?.line === line ? f.id : `${f.id}~${line ?? 0}`;
    const existing = unique.get(key);
    if (existing) unique.set(key, { ...existing, evidence: mergeEvidence(existing.evidence, f.evidence) });
    else unique.set(key, key === f.id ? f : { ...f, id: key });
  }
  return [...unique.values()];
}

const MAX_REASON_LENGTH = 200;

function scrubSuppressed(list: readonly SuppressedFinding[], secrets: ReadonlySet<string>): SuppressedFinding[] {
  return list.map((s) => ({
    ...s,
    ...(s.file ? { file: safePath(s.file) } : {}),
    ...(s.reason ? { reason: scrubText(s.reason, secrets).slice(0, MAX_REASON_LENGTH) } : {}),
  }));
}

function buildCoverage(input: ScanInput, agentsRun: number, startMs: number): Coverage {
  const stats = input.files.stats?.();
  const requests = input.requestCount?.();
  return {
    filesIndexed: input.files.paths.length,
    filesRead: stats?.read ?? 0,
    filesSkippedLarge: stats?.skippedLarge ?? 0,
    filesSkippedBinary: stats?.skippedBinary ?? 0,
    truncated: input.files.truncated === true,
    agentsRun,
    rulesInCatalog: DETERMINISTIC_RULES.length,
    durationMs: Date.now() - startMs,
    ...(requests !== undefined ? { liveRequests: requests } : {}),
  };
}

export async function runScan(input: ScanInput): Promise<ScanReport> {
  const startMs = Date.now();
  const startedAt = new Date().toISOString();
  const secrets = new Set<string>();
  const stack = await profileStack({
    files: input.files,
    ...(input.target ? { target: input.target } : {}),
    ...(input.http ? { http: input.http } : {}),
  });

  const ctx: ScanContext = {
    mode: input.mode,
    ...(input.root ? { root: input.root } : {}),
    ...(input.target ? { target: input.target } : {}),
    files: input.files,
    stack,
    ...(input.http ? { http: input.http } : {}),
    options: { ...DEFAULT_OPTIONS, ...input.options },
    registerSecret: (value: string) => {
      if (value) secrets.add(value);
    },
  };

  const squad = (input.agents ?? SQUAD).filter((a) => a.modes.includes(input.mode));
  // Promise.resolve().then so a synchronous throw inside run() is isolated like an async one.
  const settled = await Promise.allSettled(squad.map((a) => Promise.resolve().then(() => a.run(ctx))));

  const findings: Finding[] = [];
  const summaries: { id: string; name: string; findings: number; error?: string }[] = [];
  settled.forEach((result, i) => {
    const agent = squad[i] as Agent;
    if (result.status === "fulfilled") {
      findings.push(...result.value);
      summaries.push({ id: agent.id, name: agent.name, findings: result.value.length });
    } else {
      summaries.push({ id: agent.id, name: agent.name, findings: 0, error: errorMessage(result.reason) });
    }
  });

  // Snapshot before suppression so coverage reflects what the agents themselves read.
  const coverage = buildCoverage(input, squad.length, startMs);
  const { kept, suppressed } = await applySuppressions(dedupe(findings), input.files);
  const policed = input.policy ? applyPolicy(kept, input.policy) : { findings: kept, config: undefined };

  return {
    schemaVersion: 1,
    tool: "whitehat-squad",
    version: VERSION,
    target: input.targetLabel,
    mode: input.mode,
    startedAt,
    stack,
    agents: summaries.map((a) => (a.error ? { ...a, error: scrubText(a.error, secrets) } : a)),
    findings: sortFindings(
      dropOverlaps(policed.findings).map((f) => withVerifyCommand(demoteTestPaths(scrubFinding(f, secrets)), input)),
    ),
    suppressed: scrubSuppressed(suppressed, secrets),
    coverage: { ...coverage, durationMs: Date.now() - startMs },
    ...(policed.config ? { config: policed.config } : {}),
  };
}
