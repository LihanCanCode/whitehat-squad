import { createHash } from "node:crypto";
import { makeFinding } from "../core/finding.js";
import type { Finding, Severity } from "../core/types.js";
import { untrusted } from "../remediation/prompts.js";
import { ruleMeta } from "../rules/catalog.js";
import { ProviderError } from "./provider.js";
import type { LlmProvider } from "./provider.js";
import { HUNTER_SCHEMA, HUNTER_SYSTEM, hunterPrompt, PROMPT_VERSION, SEVERITIES, VALIDATOR_SCHEMA, VALIDATOR_SYSTEM, validatorPrompt } from "./prompts.js";
import type { CandidateForValidation } from "./prompts.js";
import { shownLines, verifyQuotes } from "./quotes.js";
import type { Quote } from "./quotes.js";
import { REVIEW_CLASS_IDS } from "./rules.meta.js";
import type { ReviewUnit } from "./surface.js";

export const AGENT_ID = "ai-review";
/** Prefix on every model-written fix prompt: it is advice to review, not a trusted instruction. */
export const AI_PROMPT_LABEL = "[AI-generated suggestion; review before acting] ";

export type UnitStatus = "reviewed" | "cached" | "skipped-budget" | "error";

export interface LedgerEntry {
  readonly unit: string;
  readonly status: UnitStatus;
  readonly candidates: number;
  readonly confirmed: number;
  readonly needsValidation: number;
  readonly rejected: number;
  /** Candidates dropped because a quoted line did not exist in the code shown. */
  readonly dropped: number;
  /** Candidates found but not validated because the call budget ran out (never reported as findings). */
  readonly unvalidated: number;
  /** Validator replies that did not match the contract (never treated as "rejected"). */
  readonly invalid?: number;
  readonly error?: string;
}

export interface CachedUnit {
  readonly key: string;
  readonly findings: readonly Finding[];
  readonly entry: LedgerEntry;
}

export interface ReviewCache {
  get(key: string): CachedUnit | undefined;
  set(value: CachedUnit): void;
}

export interface ReviewOptions {
  readonly target: string;
  readonly maxCalls: number;
  readonly concurrency?: number;
  readonly cache?: ReviewCache;
  readonly onProgress?: (message: string) => void;
}

export interface ReviewResult {
  readonly model: string;
  readonly findings: readonly Finding[];
  readonly ledger: readonly LedgerEntry[];
  readonly calls: number;
  readonly costUsd: number;
  readonly injectionNotices: readonly string[];
}

interface HunterCandidate extends CandidateForValidation {
  readonly severity: Severity;
  readonly fix_invariant: string;
  readonly fix_summary: string;
}

interface Verdict {
  readonly verdict: "confirmed" | "needs_validation" | "rejected";
  readonly reason: string;
  readonly evidence: readonly Quote[];
  readonly severity: Severity;
  readonly fix_summary: string;
  readonly agent_prompt: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
const str = (v: unknown, max = 600): string => (typeof v === "string" ? untrusted(v, max) : "");
const sev = (v: unknown): Severity => (SEVERITIES as readonly string[]).includes(v as string) ? (v as Severity) : "medium";

function quotes(v: unknown): Quote[] {
  if (!Array.isArray(v)) return [];
  return v.flatMap((q) =>
    isObj(q) && typeof q["file"] === "string" && Number.isInteger(q["line"]) && typeof q["quote"] === "string"
      ? [{ file: q["file"], line: q["line"] as number, quote: q["quote"] }]
      : []).slice(0, 4);
}

/** Defensive parse of hunter output. A reply that is not the contract is an error, never "no findings". */
export function parseCandidates(data: unknown): { candidates: HunterCandidate[]; notice: string } {
  if (!isObj(data) || !Array.isArray(data["candidates"])) throw new ProviderError("the model's reply did not match the hunter schema");
  const candidates = data["candidates"].slice(0, 5).flatMap((c): HunterCandidate[] => {
    if (!isObj(c) || !REVIEW_CLASS_IDS.includes(c["class"] as string)) return [];
    const evidence = quotes(c["evidence"]);
    if (evidence.length === 0) return [];
    return [{
      class: c["class"] as string,
      title: str(c["title"], 140),
      attacker: str(c["attacker"]),
      input: str(c["input"]),
      intended_control: str(c["intended_control"]),
      crossed_boundary: str(c["crossed_boundary"]),
      affected_resource: str(c["affected_resource"]),
      result: str(c["result"]),
      evidence,
      severity: sev(c["severity"]),
      fix_invariant: str(c["fix_invariant"]),
      fix_summary: str(c["fix_summary"]),
    }];
  });
  return { candidates, notice: str(data["injection_notice"], 300) };
}

export function parseVerdict(data: unknown): Verdict | undefined {
  if (!isObj(data)) return undefined;
  const verdict = data["verdict"];
  if (verdict !== "confirmed" && verdict !== "needs_validation" && verdict !== "rejected") return undefined;
  return {
    verdict,
    reason: str(data["reason"], 800),
    evidence: quotes(data["evidence"]),
    severity: sev(data["severity"]),
    fix_summary: str(data["fix_summary"]),
    agent_prompt: str(data["agent_prompt"], 1200),
  };
}

/** Cache key: everything sent for the unit, the model and the prompt version. */
export function cacheKey(u: ReviewUnit, model: string): string {
  return createHash("sha256").update(`${PROMPT_VERSION}\n${model}\n${u.id}\n${u.contentHash}`).digest("hex").slice(0, 24);
}

/** The recheck command for an AI finding (target quoted when it needs it). */
export function recheckCommand(id: string, target: string): string {
  const t = /^[\w./:\\-]+$/.test(target) ? target : `"${target.replace(/["\\$`]/g, "")}"`;
  return `whsquad review --recheck ${id} ${t}`;
}

/** Turns a validated candidate into a report finding, labelled as AI and never gating. */
export function toFinding(c: HunterCandidate, v: Verdict, evidence: readonly Quote[], model: string, target: string, unitId: string): Finding {
  const confirmed = v.verdict === "confirmed";
  const ev = evidence.map((q) => ({ file: q.file, line: q.line, snippet: untrusted(q.quote, 200) }));
  const meta = ruleMeta(c.class);
  // Labelled parts (the model writes each field as its own phrase; gluing them into one sentence reads badly).
  const end = (s: string): string => (/[.!?]$/.test(s) ? s : `${s}.`);
  const explanation = [
    `Who: ${end(c.attacker)}`,
    `Result: ${end(c.result)}`,
    `How: ${end(c.input)}`,
    `Missing control: ${end(c.intended_control)}`,
    `Affected: ${end(c.affected_resource)}`,
    `${confirmed ? "Independently confirmed" : "Needs validation"}: ${end(v.reason)}`,
  ].join(" ");
  const summary = v.fix_summary || c.fix_summary || meta?.fix || "";
  // A model-written prompt is only offered for confirmed findings, and always labelled as AI advice.
  const prompt = confirmed && v.agent_prompt ? v.agent_prompt : `Confirm this first, then enforce: ${c.fix_invariant || summary}`;
  const base = makeFinding({
    ruleId: c.class,
    agentId: AGENT_ID,
    title: c.title || meta?.title || c.class,
    severity: confirmed ? v.severity : "info",
    confidence: confirmed ? "medium" : "low",
    explanation,
    evidence: ev,
    fix: { summary, agentPrompt: `${AI_PROMPT_LABEL}${prompt}`, references: [] },
    target,
    ...(meta?.cwe ? { cwe: meta.cwe } : {}),
  });
  return {
    ...base,
    verify: { command: recheckCommand(base.id, target), ruleId: c.class, target },
    origin: "ai",
    reviewModel: model,
    reviewState: confirmed ? "confirmed" : "needs_validation",
    reviewUnit: unitId,
  };
}

/** Runs `items` with at most `limit` in flight. */
async function pool<T>(items: readonly T[], limit: number, run: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const item = items[next++] as T;
      await run(item);
    }
  });
  await Promise.all(workers);
}

interface Budget {
  /** Takes up to `n` calls; returns how many were granted. Synchronous, so concurrent workers never overspend. */
  take(n: number): number;
  readonly used: number;
}

function budgetOf(max: number): Budget {
  let left = max;
  let used = 0;
  return {
    take(n) {
      const granted = Math.max(0, Math.min(n, left));
      left -= granted;
      used += granted;
      return granted;
    },
    get used() {
      return used;
    },
  };
}

interface UnitOutcome {
  readonly findings: Finding[];
  readonly entry: LedgerEntry;
  readonly notice: string;
  readonly costUsd: number;
}

const emptyEntry = (unit: string, status: UnitStatus): LedgerEntry =>
  ({ unit, status, candidates: 0, confirmed: 0, needsValidation: 0, rejected: 0, dropped: 0, unvalidated: 0 });

const TRANSIENT = /timed out|structured_output|non-JSON|no structured output|exited with code|stopped reading/i;

/** One call, retried once on a transient CLI failure if the budget allows (the retry is a counted call). */
async function call(provider: LlmProvider, request: Parameters<LlmProvider["complete"]>[0], budget: Budget): Promise<Awaited<ReturnType<LlmProvider["complete"]>>> {
  try {
    return await provider.complete(request);
  } catch (e) {
    if (!(e instanceof ProviderError) || !TRANSIENT.test(e.message) || budget.take(1) === 0) throw e;
    return provider.complete(request);
  }
}

/** Hunt one unit, quote-check its candidates, then validate them with calls reserved up front. */
async function reviewUnit(u: ReviewUnit, provider: LlmProvider, budget: Budget, options: ReviewOptions): Promise<UnitOutcome> {
  if (budget.take(1) === 0) return { findings: [], entry: emptyEntry(u.id, "skipped-budget"), notice: "", costUsd: 0 };
  const progress = options.onProgress ?? (() => undefined);
  progress(`hunting ${u.id}`);
  const shown = shownLines(u);
  const findings: Finding[] = [];
  const counts = { candidates: 0, confirmed: 0, needsValidation: 0, rejected: 0, dropped: 0, unvalidated: 0, invalid: 0 };
  let costUsd = 0;
  let notice = "";
  try {
    const hunt = await call(provider, { system: HUNTER_SYSTEM, prompt: hunterPrompt(u), schema: HUNTER_SCHEMA }, budget);
    costUsd += hunt.costUsd ?? 0;
    const parsed = parseCandidates(hunt.data);
    notice = parsed.notice;
    counts.candidates = parsed.candidates.length;
    const real = parsed.candidates.flatMap((c) => {
      const ev = verifyQuotes(c.evidence, shown);
      if (!ev) counts.dropped += 1;
      return ev ? [{ c, ev }] : [];
    });
    // Reserve this unit's validators now, before any other worker can start a new hunt.
    const granted = budget.take(real.length);
    counts.unvalidated = real.length - granted;
    for (const { c, ev } of real.slice(0, granted)) {
      progress(`validating ${c.class} in ${u.id}`);
      const check = await call(provider, { system: VALIDATOR_SYSTEM, prompt: validatorPrompt(u, { ...c, evidence: ev }), schema: VALIDATOR_SCHEMA }, budget);
      costUsd += check.costUsd ?? 0;
      const v = parseVerdict(check.data);
      if (!v) {
        counts.invalid += 1;
        continue;
      }
      if (v.verdict === "rejected") {
        counts.rejected += 1;
        continue;
      }
      // The validator's own citations must be real too; if not, keep the hunter's verified ones.
      const evidence = (v.evidence.length > 0 && verifyQuotes(v.evidence, shown)) || ev;
      if (v.verdict === "confirmed") counts.confirmed += 1;
      else counts.needsValidation += 1;
      findings.push(toFinding(c, v, evidence, provider.model, options.target, u.id));
    }
    const { invalid, ...rest } = counts;
    return { findings, entry: { unit: u.id, status: "reviewed", ...rest, ...(invalid > 0 ? { invalid } : {}) }, notice, costUsd };
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    const { invalid, ...rest } = counts;
    return { findings, entry: { unit: u.id, status: "error", ...rest, ...(invalid > 0 ? { invalid } : {}), error }, notice, costUsd };
  }
}

/** A unit result is reusable only when it is complete: no errors, no invalid replies, nothing unvalidated. */
const cacheable = (e: LedgerEntry): boolean => e.status === "reviewed" && e.unvalidated === 0 && (e.invalid ?? 0) === 0;

/**
 * Hunt → mechanical quote check → independent validation, per unit, highest-risk units first.
 * `maxCalls` is a hard ceiling; candidates that cannot be validated within it are counted in the
 * ledger and never reported as findings.
 */
export async function runReview(units: readonly ReviewUnit[], provider: LlmProvider, options: ReviewOptions): Promise<ReviewResult> {
  const budget = budgetOf(options.maxCalls);
  const results = new Map<string, UnitOutcome>();
  await pool(units, options.concurrency ?? 2, async (u) => {
    const key = cacheKey(u, provider.model);
    const cached = options.cache?.get(key);
    if (cached) {
      results.set(u.id, { findings: [...cached.findings], entry: { ...cached.entry, status: "cached" }, notice: "", costUsd: 0 });
      return;
    }
    const outcome = await reviewUnit(u, provider, budget, options);
    results.set(u.id, outcome);
    if (cacheable(outcome.entry)) options.cache?.set({ key, findings: outcome.findings, entry: outcome.entry });
  });

  const ordered = units.map((u) => results.get(u.id)).filter((r): r is UnitOutcome => r !== undefined);
  const seen = new Set<string>();
  const findings = ordered.flatMap((r) => r.findings).filter((f) => {
    const k = `${f.ruleId}|${f.evidence[0]?.file}|${f.evidence[0]?.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return {
    model: provider.model,
    findings,
    ledger: ordered.map((r) => r.entry),
    calls: budget.used,
    costUsd: ordered.reduce((n, r) => n + r.costUsd, 0),
    injectionNotices: ordered.filter((r) => r.notice).map((r) => `${r.entry.unit}: ${r.notice}`),
  };
}
