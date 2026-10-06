import { promises as fs } from "node:fs";
import path from "node:path";
import type { RemediationPlan, ScanReport } from "../core/types.js";
import { applyFixes } from "../remediation/apply.js";
import { buildRemediationPlan } from "../remediation/plan.js";
import { renderPlanDocument, renderPlanText } from "../remediation/render.js";
import { terminalWidth, wrapToWidth } from "../reporters/wrap.js";
import { renderTriagePack, type ReadFile } from "../remediation/triage.js";
import { UsageError, type CliOptions } from "./args.js";
import { EXIT, type ExitCode } from "./exit-codes.js";
import { isUrlTarget, scanTarget } from "./run-scan.js";

const MAX_WINDOW_FILE_BYTES = 1_000_000;

/** Attaches the fix plan. Done here, after the scan, so the orchestrator stays a pure finder. */
export function withRemediation(report: ScanReport): ScanReport {
  return { ...report, remediation: buildRemediationPlan(report) };
}

/** Reads scanned files for triage code windows; refuses anything outside the project root. */
export function rootReader(root: string): ReadFile {
  const base = path.resolve(root);
  return async (rel) => {
    const full = path.resolve(base, rel);
    const inside = path.relative(base, full);
    if (inside === "" || inside.startsWith("..") || path.isAbsolute(inside)) return null;
    try {
      const stat = await fs.stat(full);
      if (!stat.isFile() || stat.size > MAX_WINDOW_FILE_BYTES) return null;
      return await fs.readFile(full, "utf8");
    } catch {
      return null;
    }
  };
}

export interface FixDeps {
  readonly out: (text: string) => void;
  readonly err: (text: string) => void;
  readonly save: (report: ScanReport) => Promise<void>;
  readonly now?: () => Date;
}

function verifyCommands(report: ScanReport, plan: RemediationPlan): string[] {
  const inPlan = new Set(plan.steps.flatMap((s) => s.findingIds));
  return [...new Set(report.findings.filter((f) => inPlan.has(f.id)).map((f) => f.verify.command))];
}

function render(report: ScanReport, plan: RemediationPlan, format: string): string | null {
  switch (format) {
    case "prompt":
      return plan.masterPrompt;
    case "json":
      return JSON.stringify(plan, null, 2) + "\n";
    case "markdown":
      return renderPlanDocument(plan, report.target);
    case "terminal":
      // Wrap the steps to the terminal; the SQL block stays as is so it can be copied.
      return wrapToWidth(renderPlanText(plan), terminalWidth(), "Merged SQL migration:");
    default:
      return null;
  }
}

/** `whsquad fix [path]`: scan (static only), print the plan; with --write apply the safe, additive subset. */
export async function cmdFix(target: string | undefined, options: CliOptions, deps: FixDeps): Promise<ExitCode> {
  const root = target ?? ".";
  if (isUrlTarget(root)) {
    throw new UsageError("fix works on a local project folder, not a URL: it plans changes to your code. Scan the folder instead.");
  }
  if (options.format === "sarif") throw new UsageError("fix supports --format terminal, markdown, json, prompt or triage.");
  if (options.write && options.format !== "terminal") throw new UsageError("--write only works with the default terminal format.");
  const report = withRemediation(await scanTarget(root, options));
  const plan = report.remediation as RemediationPlan;
  await deps.save(report);
  const incomplete = report.agents.some((a) => a.error);
  if (incomplete) deps.err("Scan incomplete: one or more agents failed, so this plan may be missing steps.");
  if (options.write && incomplete) {
    deps.err("Refusing --write: the scan was incomplete. Fix the failing agent (or re-run) first.");
    return EXIT.INTERNAL;
  }

  const rendered = options.format === "triage" ? await renderTriagePack(report, rootReader(root)) : render(report, plan, options.format);
  if (rendered === null) throw new UsageError(`Unsupported --format "${options.format}" for fix.`);
  if (options.out) {
    await fs.writeFile(options.out, rendered, "utf8");
    deps.err(`Written to ${options.out}`);
  } else {
    deps.out(rendered);
  }
  if (!options.write) {
    if (options.format === "terminal" && plan.steps.length > 0) {
      deps.err("Dry run: nothing was changed. Run again with --write to apply only the safe additive changes (.gitignore lines, one new migration, .whsquad/fix-plan.md).");
    }
    return EXIT.CLEAN;
  }

  const result = await applyFixes(report, plan, path.resolve(root), deps.now);
  const width = terminalWidth();
  deps.out(wrapToWidth(["", "Changed:", ...(result.changed.length > 0 ? result.changed.map((c) => `  + ${c}`) : ["  (nothing)"])].join("\n"), width));
  if (result.skipped.length > 0) deps.out(wrapToWidth(["Left alone:", ...result.skipped.map((s) => `  - ${s}`)].join("\n"), width));
  const verify = verifyCommands(report, plan);
  if (verify.length > 0) deps.out(["", "Now work through the plan, then verify:", ...verify.map((v) => `  ${v}`)].join("\n"));
  return EXIT.CLEAN;
}
