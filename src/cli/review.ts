import { promises as fs } from "node:fs";
import path from "node:path";
import { indexDirectory } from "../core/fs-walk.js";
import type { Finding, ScanReport } from "../core/types.js";
import { renderReport } from "../reporters/index.js";
import { stripControl } from "../reporters/util.js";
import { cacheKey, parseVerdict, recheckCommand, runReview } from "../review/pipeline.js";
import type { ReviewResult } from "../review/pipeline.js";
import { recheckPrompt, VALIDATOR_SCHEMA, VALIDATOR_SYSTEM } from "../review/prompts.js";
import { ClaudeCliProvider, resolveClaudeExecutable } from "../review/provider.js";
import type { LlmProvider } from "../review/provider.js";
import { shownLines, verifyQuotes } from "../review/quotes.js";
import { buildUnits, envSecrets } from "../review/surface.js";
import type { ReviewUnit } from "../review/surface.js";
import { FileReviewCache, loadLastReview, makeSandbox, reviewPaths, saveLastReview, StateError } from "../review/store.js";
import type { ReviewPaths } from "../review/store.js";
import type { CliOptions } from "./args.js";
import { UsageError } from "./args.js";
import { EXIT, type ExitCode } from "./exit-codes.js";
import { isUrlTarget, scanTarget, TargetError } from "./run-scan.js";

export interface ReviewDeps {
  readonly out: (s: string) => void;
  readonly err: (s: string) => void;
  /** Injected in tests; defaults to the Claude Code CLI. */
  readonly provider?: (model: string, sandboxDir: string) => LlmProvider;
}

const clean = (s: unknown): string => stripControl(String(s ?? "")).replace(/\s+/g, " ").trim();
const short = (s: unknown, max: number): string => {
  const c = clean(s);
  return c.length > max ? `${c.slice(0, max - 1)}…` : c;
};

function planText(units: readonly ReviewUnit[], cached: number, options: CliOptions, target: string, claude: string | undefined, paths: ReviewPaths): string {
  const uncached = units.length - cached;
  const omitted = units.flatMap((u) => u.omitted);
  return [
    `whitehat-squad AI review plan for ${clean(target)} (dry run: nothing was sent)`,
    `Model: ${options.model} via your Claude Code CLI (your plan; no API key): ${claude ? clean(claude) : "NOT FOUND on PATH"}.`,
    `Tools disabled. Runs in a fresh private folder under ${clean(paths.sandboxRoot)}.`,
    "",
    `${units.length} unit${units.length === 1 ? "" : "s"} (${cached} unchanged since the last review, ${uncached} to send), highest risk first:`,
    ...units.slice(0, 25).map((u) => `  ${String(u.score).padStart(2)}  ${u.kind.padEnd(7)} ${short(u.id, 120)}  (guards: ${u.guards.length ? u.guards.join(", ") : "none"})${u.truncatedLines ? `  [${u.truncatedLines} lines not shown]` : ""}`),
    ...(units.length > 25 ? [`  ... and ${units.length - 25} more`] : []),
    ...(omitted.length ? [`  Not sent (size limit): ${omitted.map((o) => short(o, 80)).join(", ")}`] : []),
    "",
    `Calls: 1 hunter per unit to send + 1 validator per surviving candidate, capped at --max-calls ${options.maxCalls}.`,
    ...(uncached > options.maxCalls ? [`Warning: ${uncached} units need a hunter call but --max-calls is ${options.maxCalls}; the lowest-risk ones will be skipped.`] : []),
    "Sent: each unit's code and up to 3 local code files it imports, line-numbered, secrets redacted. .env, key and credential files are never sent.",
    "",
    `Run it: whsquad review ${clean(target)} --yes${options.model !== "sonnet" ? ` --model ${options.model}` : ""}`,
  ].join("\n");
}

/** Terminal view: Who / Result / Missing control, each trimmed; the full text stays in JSON and markdown. */
function explanationLines(explanation: string): string[] {
  const parts = [...clean(explanation).matchAll(/(Who|Result|Missing control|Independently confirmed|Needs validation): (.*?)(?= (?:Who|Result|How|Missing control|Affected|Independently confirmed|Needs validation): |$)/g)];
  if (parts.length === 0) return [`  ${short(explanation, 400)}`];
  return parts.map((m) => `  ${(m[1] ?? "").toLowerCase()}: ${short(m[2] ?? "", m[1] === "Result" ? 220 : 160)}`);
}

function renderFinding(f: Finding, target: string): string[] {
  const e = f.evidence[0];
  return [
    `[${clean(f.severity).toUpperCase()}] [AI] ${short(f.title, 160)}  (${clean(f.id)})  ${clean(f.ruleId)}`,
    ...(e?.file ? [`  at: ${short(`${e.file}:${e.line ?? ""}`, 200)}`] : []),
    ...explanationLines(f.explanation),
    `  fix: ${short(f.fix.summary, 260)}`,
    // Rebuilt from the id, never taken from stored data.
    `  recheck: ${recheckCommand(clean(f.id), target)}`,
  ];
}

export function renderReviewText(r: ReviewResult, target: string): string {
  const confirmed = r.findings.filter((f) => f.reviewState === "confirmed");
  const needs = r.findings.filter((f) => f.reviewState === "needs_validation");
  const by = (s: string) => r.ledger.filter((l) => l.status === s).length;
  const sum = (k: "dropped" | "rejected" | "unvalidated" | "invalid") => r.ledger.reduce((n, l) => n + (l[k] ?? 0), 0);
  const out = [`whitehat-squad AI review of ${clean(target)}  (model: ${clean(r.model)} via Claude Code)`, ""];
  if (confirmed.length === 0) out.push("No confirmed AI findings.", "");
  for (const f of confirmed) out.push(...renderFinding(f, target), "");
  if (needs.length > 0) {
    out.push(`Needs validation (${needs.length}): real paths whose decisive fact is outside the code`);
    for (const f of needs) out.push(`  - ${short(f.title, 160)} (${clean(f.ruleId)}, ${short(`${f.evidence[0]?.file ?? ""}:${f.evidence[0]?.line ?? ""}`, 160)})`);
    out.push("");
  }
  const errors = r.ledger.filter((l) => l.status === "error");
  out.push(
    `Coverage: ${by("reviewed") + by("cached")} of ${r.ledger.length} units reviewed (${by("cached")} from cache), ${by("skipped-budget")} skipped (call budget), ${errors.length} failed.`,
    `Candidates: ${sum("rejected")} rejected by the independent check, ${sum("dropped")} dropped (quoted code did not exist), ${sum("unvalidated")} not validated (budget)${sum("invalid") ? `, ${sum("invalid")} unusable validator replies` : ""}.`,
    `Model calls: ${r.calls}${r.costUsd > 0 ? ` (list-price equivalent $${r.costUsd.toFixed(2)}; billed to your Claude Code plan)` : ""}.`,
  );
  for (const e of errors.slice(0, 3)) out.push(`  failed: ${short(e.unit, 120)}: ${short(e.error, 200)}`);
  for (const n of r.injectionNotices.slice(0, 5)) out.push(`Warning: repository text tried to instruct the model: ${short(n, 300)}`);
  out.push("AI findings are advisory: they never change the exit code. Rule-based findings: whsquad scan.");
  return out.join("\n");
}

/** Markdown/SARIF view: AI findings only, titles tagged; the scan's plan/coverage/suppressions do not apply. */
function asReport(base: ScanReport, r: ReviewResult): ScanReport {
  const { remediation: _r, coverage: _c, suppressed: _s, config: _cfg, ...rest } = base;
  const findings = r.findings.map((f) => ({ ...f, title: `[AI${f.reviewState === "needs_validation" ? ", needs validation" : ""}] ${f.title}` }));
  return { ...rest, findings, agents: [{ id: "ai-review", name: `AI review (${r.model})`, findings: findings.length }] };
}

/** The unit a stored finding came from: by its unit id, else by any cited file (incl. imported helpers). */
function unitFor(units: readonly ReviewUnit[], f: Finding): ReviewUnit | undefined {
  const byId = f.reviewUnit ? units.find((u) => u.id === f.reviewUnit) : undefined;
  if (byId) return byId;
  const files = f.evidence.map((e) => e.file).filter((x): x is string => typeof x === "string");
  if (files.some((x) => x.endsWith(".sql"))) return units.find((u) => u.kind === "sql");
  return units.find((u) => files.includes(u.file)) ?? units.find((u) => u.related.some((r) => files.includes(r.file)));
}

async function recheck(root: string, target: string, options: CliOptions, provider: LlmProvider, paths: ReviewPaths, deps: ReviewDeps): Promise<ExitCode> {
  const id = options.recheck ?? "";
  const last = await loadLastReview(paths);
  const finding = last?.result.findings.find((f) => f.id === id);
  if (!finding) throw new UsageError(`No AI finding "${clean(id)}" in the last review of this folder. Run "whsquad review ${clean(target)} --yes" first.`);
  const report = await scanTarget(target, { ...options, noConfig: true });
  const files = await indexDirectory(root);
  const units = await buildUnits(files, report.findings, await envSecrets(files));
  const unit = unitFor(units, finding);
  deps.out(`Recheck ${clean(finding.ruleId)} [AI] ${short(finding.title, 160)}`);
  if (!unit) {
    deps.out("  GONE           the handler or file this finding pointed at no longer exists.");
    return EXIT.CLEAN;
  }
  const res = await provider.complete({ system: VALIDATOR_SYSTEM, prompt: recheckPrompt(unit, finding), schema: VALIDATOR_SCHEMA });
  const v = parseVerdict(res.data);
  if (!v || (v.verdict !== "rejected" && v.evidence.length > 0 && !verifyQuotes(v.evidence, shownLines(unit)))) {
    deps.out("  UNCERTAIN      the model's answer was unusable (or cited code that does not exist); run the recheck again.");
    return EXIT.FINDINGS;
  }
  if (v.verdict === "rejected") {
    deps.out(`  FIXED          ${short(v.reason, 300)}`);
    deps.out("Result: the independent check no longer finds this issue (AI-judged; review the change yourself).");
    return EXIT.CLEAN;
  }
  deps.out(`  STILL PRESENT  ${short(v.reason, 300)}`);
  return EXIT.FINDINGS;
}

function render(result: ReviewResult, report: ScanReport, target: string, format: CliOptions["format"]): string {
  if (format === "json") return JSON.stringify(result, null, 2);
  if (format === "terminal") return renderReviewText(result, target);
  return renderReport(asReport(report, result), format as Exclude<CliOptions["format"], "triage">, { color: false });
}

/** `whsquad review [path]`: opt-in AI review grounded in the deterministic scan. Never gates CI. */
export async function cmdReview(target: string | undefined, options: CliOptions, deps: ReviewDeps): Promise<ExitCode> {
  const t = target ?? ".";
  if (isUrlTarget(t)) throw new UsageError("review works on a local project folder, not a URL.");
  const root = path.resolve(t);
  const stat = await fs.stat(root).catch(() => null);
  if (!stat?.isDirectory()) throw new TargetError(`"${t}" is not a directory.`);
  if (options.format === "triage" || options.format === "prompt") throw new UsageError("review supports --format terminal, json, markdown or sarif.");
  let paths: ReviewPaths;
  try {
    paths = reviewPaths(root);
  } catch (e) {
    if (e instanceof StateError) throw new UsageError(e.message);
    throw e;
  }
  const claude = resolveClaudeExecutable(process.env, process.platform, root);
  if (!deps.provider && (options.yes || options.recheck) && !claude) {
    throw new UsageError('Claude Code was not found on PATH (entries inside the project are ignored). Install it and run "claude" once to sign in.');
  }
  const makeProvider = deps.provider ?? ((model: string, dir: string) => new ClaudeCliProvider({ model, sandboxDir: dir, ...(claude ? { command: claude } : {}) }));

  if (!options.yes && !options.recheck) {
    const report = await scanTarget(t, { ...options, noConfig: true });
    const files = await indexDirectory(root);
    const units = await buildUnits(files, report.findings);
    const cache = new FileReviewCache(paths);
    await cache.load();
    const cached = units.filter((u) => cache.get(cacheKey(u, options.model))).length;
    deps.out(planText(units, cached, options, t, claude, paths));
    return EXIT.CLEAN;
  }

  const sandbox = await makeSandbox(paths);
  try {
    const provider = makeProvider(options.model, sandbox);
    if (options.recheck) return await recheck(root, t, options, provider, paths, deps);
    return await runAndReport(root, t, options, provider, paths, deps);
  } finally {
    await fs.rm(sandbox, { recursive: true, force: true }).catch(() => undefined);
  }
}

async function runAndReport(root: string, t: string, options: CliOptions, provider: LlmProvider, paths: ReviewPaths, deps: ReviewDeps): Promise<ExitCode> {
  // Ground truth first: the deterministic scan (free, offline) seeds every unit's context.
  const report = await scanTarget(t, { ...options, noConfig: true });
  const files = await indexDirectory(root);
  const units = await buildUnits(files, report.findings, await envSecrets(files));
  if (units.length === 0) {
    deps.out("Nothing to review: no route handlers, Server Actions or database policies were found.");
    return EXIT.CLEAN;
  }
  const cache = new FileReviewCache(paths);
  await cache.load();
  const result = await runReview(units, provider, {
    target: t, maxCalls: options.maxCalls, concurrency: options.concurrency, cache, onProgress: (m) => deps.err(`  ${short(m, 200)}`),
  });
  await cache.save();
  await saveLastReview(paths, t, result);
  const rendered = render(result, report, t, options.format);
  if (options.out) {
    await fs.writeFile(options.out, rendered, "utf8");
    deps.err(`Review written to ${options.out}`);
  } else {
    deps.out(rendered);
  }
  // Advisory only: AI findings never change the exit code. A review where every unit failed is an error.
  return result.ledger.length > 0 && result.ledger.every((l) => l.status === "error") ? EXIT.INTERNAL : EXIT.CLEAN;
}
