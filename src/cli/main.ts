import { promises as fs } from "node:fs";
import path from "node:path";
import { SQUAD } from "../core/registry.js";
import { VERSION } from "../core/orchestrator.js";
import { meetsThreshold } from "../core/severity.js";
import type { ScanReport } from "../core/types.js";
import { createProof } from "../safety/ownership.js";
import { assertSafeTarget, UnsafeWriteError } from "../safety/safe-write.js";
import { renderReport, type ReportFormat } from "../reporters/index.js";
import { colorEnabled } from "../reporters/terminal.js";
import { paintStatus, terminalWidth, wrapToWidth } from "../reporters/wrap.js";
import { HELP, parseCli, UsageError, type CliOptions } from "./args.js";
import { buildBaseline } from "./baseline.js";
import { EXIT, type ExitCode } from "./exit-codes.js";
import { cmdFix, withRemediation } from "./fix.js";
import { cmdReview } from "./review.js";
import { createFsWatcher } from "./fs-watcher.js";
import {
  isUrlTarget, loadLastReport, OwnershipError, saveLastReport, scanTarget, STATE_DIR, TargetError,
} from "./run-scan.js";
import { findRule, renderExplain, renderRules, selectRules } from "./rules-cmd.js";
import { compareRule, formatVerify, verifyExitIsClean } from "./verify.js";
import { runWatch } from "./watch.js";

const out = (text: string): void => void process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
const err = (text: string): void => void process.stderr.write(text.endsWith("\n") ? text : `${text}\n`);

async function cmdScan(target: string | undefined, options: CliOptions): Promise<ExitCode> {
  if (!target) throw new UsageError("scan needs a target: a project folder or a URL you own.");
  if (options.format === "triage") throw new UsageError('--format triage belongs to "whsquad fix".');
  const report = withRemediation(await scanTarget(target, options));
  await saveStateBestEffort(report);

  // A file never gets colour; otherwise the reporter decides (TTY, NO_COLOR, FORCE_COLOR).
  const color = options.color ?? (options.out ? false : undefined);
  const text = renderReport(report, options.format as ReportFormat, { ...(color === undefined ? {} : { color }), showSuppressed: options.showSuppressed });
  const rendered = options.format === "terminal" && !options.out ? wrapToWidth(text, terminalWidth()) : text;
  if (options.out) {
    await fs.writeFile(options.out, rendered, "utf8");
    err(`Report written to ${options.out}`);
  } else {
    out(rendered);
  }
  if (report.mode === "live" && !options.probeDatabase && (report.stack.supabaseUrl || report.stack.firebaseProjectId)) {
    err("Tip: this site uses a Supabase/Firebase backend. Re-run with --probe-database to test whether its tables are publicly readable (reads at most 1 row per table).");
  }
  const incomplete = report.agents.some((a) => a.error);
  if (incomplete) err("Scan incomplete: one or more agents failed, so a clean result cannot be trusted.");
  // Low-confidence heuristics and known (baseline) findings are shown but never fail a build on their own.
  const threshold = options.failOnExplicit ? options.failOn : (report.config?.failOn ?? options.failOn);
  const failing = report.findings.some((f) => !f.baseline && f.confidence !== "low" && meetsThreshold(f.severity, threshold));
  if (failing) return EXIT.FINDINGS;
  return incomplete ? EXIT.INTERNAL : EXIT.CLEAN;
}

/** The previous-scan baseline is a convenience for `verify`; a read-only cwd must not kill the scan. */
async function saveStateBestEffort(report: ScanReport): Promise<void> {
  try {
    await saveLastReport(report);
  } catch (e) {
    err(`Warning: could not save .whsquad/last-report.json (${e instanceof Error ? e.message : String(e)}); "verify" will not work.`);
  }
}

function normalizedUrl(target: string): string {
  try {
    return new URL(target).href;
  } catch {
    throw new UsageError(`"${target}" is not a valid URL.`);
  }
}

function sameTarget(a: string, b: string): boolean {
  if (isUrlTarget(a) || isUrlTarget(b)) return isUrlTarget(a) && isUrlTarget(b) && normalizedUrl(a) === normalizedUrl(b);
  return path.resolve(a) === path.resolve(b);
}

async function cmdVerify(ruleId: string | undefined, target: string | undefined, options: CliOptions): Promise<ExitCode> {
  if (!ruleId || !target) throw new UsageError("verify needs a rule id and a target: whsquad verify SEC-001 .");
  if (isUrlTarget(target)) normalizedUrl(target);
  const before = await loadLastReport();
  if (!before) throw new UsageError("No previous scan found. Run \"whsquad scan <target>\" first.");
  if (!sameTarget(before.target, target)) {
    throw new UsageError(`The last scan was of "${before.target}", not "${target}". Run "whsquad scan ${target}" first.`);
  }
  const rule = ruleId.toUpperCase();
  if (!before.findings.some((f) => f.ruleId === rule)) {
    throw new UsageError(`The last scan of ${before.target} had no ${rule} findings, so there is nothing to verify.`);
  }
  // Re-run the original scan: a finding that needed --git-history or --probe-database must be re-checked with it.
  const original = before.scanOptions;
  const rescanOptions: CliOptions = {
    ...options,
    gitHistory: options.gitHistory || (original?.gitHistory ?? false),
    probeDatabase: options.probeDatabase || (original?.probeDatabase ?? false),
    allowPrivate: options.allowPrivate || (original?.allowPrivate ?? false),
  };
  const after = await scanTarget(target, rescanOptions);
  if (after.agents.some((a) => a.error)) {
    err("Cannot verify: an agent failed during the re-scan, so a missing finding may not mean it was fixed.");
    return EXIT.INTERNAL;
  }
  const result = compareRule(rule, before, after);
  out(statusText(formatVerify(result), options));
  await saveStateBestEffort(after);
  return verifyExitIsClean(result) ? EXIT.CLEAN : EXIT.FINDINGS;
}

/**
 * Records every current finding as "known": later `scan --baseline` runs show them but only fail
 * on findings that are new since now. Refuses to write from an incomplete scan.
 */
async function cmdBaseline(target: string | undefined, options: CliOptions): Promise<ExitCode> {
  const report = await scanTarget(target ?? ".", options, process.cwd(), { ignoreBaseline: true });
  if (report.agents.some((a) => a.error)) {
    err("Baseline not written: an agent failed, so the list of current findings would be incomplete.");
    return EXIT.INTERNAL;
  }
  const file = options.out ?? path.join(process.cwd(), STATE_DIR, "baseline.json");
  // An explicit --out is the user's own choice; the default lives in the (possibly hostile) repo.
  if (options.out === undefined) await assertSafeTarget(process.cwd(), file);
  await fs.mkdir(path.dirname(path.resolve(file)), { recursive: true });
  await fs.writeFile(file, JSON.stringify(buildBaseline(report), null, 2) + "\n", "utf8");
  out(`Baseline written to ${file} (${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}). Use it with: whsquad scan ${target ?? "."} --baseline ${file}`);
  return EXIT.CLEAN;
}

function cmdRules(options: CliOptions): ExitCode {
  out(renderRules(selectRules(options.agent), options.format));
  return EXIT.CLEAN;
}

function cmdExplain(ruleId: string | undefined, options: CliOptions): ExitCode {
  if (!ruleId) throw new UsageError("explain needs a rule id: whsquad explain DB-001. List them with \"whsquad rules\".");
  out(renderExplain(findRule(ruleId), options.format));
  return EXIT.CLEAN;
}

/**
 * Re-scans `root` on every file change and prints only what changed since the last scan — the
 * "keep this open while you vibe-code" mode for Claude Code / Cursor / Codex / a plain terminal.
 */
/** verify/watch lines: FIXED green, NEW / STILL PRESENT red, wrapped to the terminal. */
function statusText(text: string, options: CliOptions): string {
  const color = colorEnabled(options.color === undefined ? {} : { color: options.color });
  return wrapToWidth(paintStatus(text, color), terminalWidth());
}

async function cmdWatch(target: string | undefined, options: CliOptions): Promise<ExitCode> {
  const root = target ?? ".";
  if (isUrlTarget(root)) throw new UsageError("watch only works on a local folder, not a URL. Use \"scan\" for a live site.");
  const stat = await fs.stat(path.resolve(root)).catch(() => null);
  if (!stat?.isDirectory()) throw new TargetError(`"${root}" is not a directory.`);
  out(`Watching ${root} for changes. Press Ctrl+C to stop.`);
  let watcherFailed = false;
  let stopWaiting: () => void = () => undefined;
  const waiting = new Promise<void>((resolve) => {
    stopWaiting = resolve;
  });
  const stop = await runWatch(root, {
    scan: () => scanTarget(root, options),
    watch: (r, onChange) =>
      createFsWatcher(r, onChange, {
        onError: (e) => {
          watcherFailed = true;
          err(`File watcher failed (${e.message}); stopped watching. Re-run "whsquad watch" to resume.`);
          stopWaiting();
        },
      }),
    out: (line) => out(statusText(line, options)),
    err,
  });
  process.once("SIGINT", stopWaiting);
  await waiting;
  stop();
  process.removeListener("SIGINT", stopWaiting);
  return watcherFailed ? EXIT.INTERNAL : EXIT.CLEAN;
}

async function cmdInitProof(domain: string | undefined): Promise<ExitCode> {
  if (!domain || isUrlTarget(domain)) throw new UsageError("init-proof needs a bare domain: whsquad init-proof example.com");
  const { token, file } = createProof(domain, path.join(process.cwd(), STATE_DIR));
  out(
    `Ownership token created (saved to ${file}; keep it out of git).\n\n` +
      `Prove you own ${domain} with ONE of:\n` +
      `  1. DNS TXT record   _whsquad.${domain}   =   whsquad-verify=${token}\n` +
      `  2. File             https://${domain}/.well-known/whsquad.txt   containing   ${token}\n\n` +
      `Then run: whsquad scan https://${domain}`,
  );
  return EXIT.CLEAN;
}

function cmdAgents(): ExitCode {
  out(SQUAD.map((a) => `${a.name.padEnd(14)} ${a.role}  [${a.modes.join(", ")}]`).join("\n"));
  return EXIT.CLEAN;
}

/** Runs the CLI and returns the process exit code. Never calls process.exit. */
export async function main(argv: readonly string[]): Promise<ExitCode> {
  try {
    const { command, positionals, options } = parseCli(argv);
    if (options.version) {
      out(VERSION);
      return EXIT.CLEAN;
    }
    if (options.help || !command) {
      out(HELP);
      return command || options.help ? EXIT.CLEAN : EXIT.USAGE;
    }
    switch (command) {
      case "scan":
        return await cmdScan(positionals[0], options);
      case "review":
        return await cmdReview(positionals[0], options, { out, err });
      case "fix":
        return await cmdFix(positionals[0], options, { out, err, save: saveStateBestEffort });
      case "verify":
        return await cmdVerify(positionals[0], positionals[1], options);
      case "watch":
        return await cmdWatch(positionals[0], options);
      case "baseline":
        return await cmdBaseline(positionals[0], options);
      case "rules":
        return cmdRules(options);
      case "explain":
        return cmdExplain(positionals[0], options);
      case "init-proof":
        return await cmdInitProof(positionals[0]);
      case "agents":
        return cmdAgents();
      default:
        throw new UsageError(`Unknown command "${command}". Run "whsquad --help".`);
    }
  } catch (e) {
    if (e instanceof UsageError || e instanceof TargetError) {
      err(`Error: ${e.message}`);
      return EXIT.USAGE;
    }
    if (e instanceof OwnershipError) {
      err(e.message);
      return EXIT.OWNERSHIP;
    }
    if (e instanceof UnsafeWriteError) {
      err(`Refused: ${e.message}. Nothing was written.`);
      return EXIT.INTERNAL;
    }
    err(`Internal error: ${e instanceof Error ? e.message : String(e)}`);
    return EXIT.INTERNAL;
  }
}
