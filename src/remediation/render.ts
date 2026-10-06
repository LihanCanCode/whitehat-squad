import type { RemediationPlan, RemediationStep } from "../core/types.js";
import { code, esc, escLine, fence } from "../reporters/md-util.js";
import { stripControl } from "../reporters/util.js";

const oneLine = (s: string): string => stripControl(s).replace(/\s+/g, " ").trim();
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

function findingCount(plan: RemediationPlan): number {
  return plan.steps.reduce((n, s) => n + s.findingIds.length, 0);
}

function stepMarkdown(s: RemediationStep, i: number, h: string): string[] {
  const lines = [
    `${h} ${i + 1}. ${escLine(s.title)}`,
    "",
    `**Phase ${s.phase}: ${escLine(s.phaseName)}** | **Severity:** ${s.severityMax} | **Rules:** ${s.ruleIds.map(code).join(", ")}`,
    "",
    esc(s.summary),
    "",
    `Findings: ${s.findingIds.map(code).join(", ")}`,
  ];
  if (s.files.length > 0) lines.push("", `Files: ${s.files.map(code).join(", ")}`);
  if (s.commands) lines.push("", fence(s.commands.join("\n"), "bash"));
  lines.push("");
  return lines;
}

/** Markdown body of the plan; `level` is the heading depth of its sections (2 inside a report). */
function planBody(plan: RemediationPlan, level: number): string[] {
  const h = "#".repeat(level + 1);
  const lines: string[] = [];
  if (plan.steps.length === 0) lines.push("Nothing to fix automatically.", "");
  else lines.push(`${plural(plan.steps.length, "step")} covering ${plural(findingCount(plan), "finding")}, in the order to fix them.`, "");
  plan.steps.forEach((s, i) => lines.push(...stepMarkdown(s, i, h)));
  if (plan.review.length > 0) {
    lines.push(
      `${h} Review before acting`,
      "",
      `${plural(plan.review.length, "finding")} left out of the plan (low confidence or already known): ${plan.review.map(code).join(", ")}. Validate them with \`whsquad fix --format triage\`.`,
      "",
    );
  }
  if (plan.migrationSql) lines.push(`${h} Merged SQL migration`, "", fence(plan.migrationSql, "sql"), "");
  lines.push(`${h} Master prompt`, "", "Paste this into your coding agent:", "", fence(plan.masterPrompt, "text"), "");
  return lines;
}

/** The "Fix plan" section embedded in the markdown report. */
export function renderPlanSection(plan: RemediationPlan): string[] {
  return ["## Fix plan", "", ...planBody(plan, 2)];
}

/** The standalone `.whsquad/fix-plan.md` document. */
export function renderPlanDocument(plan: RemediationPlan, target: string): string {
  return ["# whitehat-squad fix plan", "", `Target: ${escLine(target)}`, "", ...planBody(plan, 1)].join("\n");
}

/** Terminal text for `whsquad fix` (dry run). */
export function renderPlanText(plan: RemediationPlan): string {
  const lines: string[] = [];
  if (plan.steps.length === 0) {
    lines.push("Fix plan: nothing to fix automatically.");
  } else {
    lines.push(`Fix plan: ${plural(plan.steps.length, "step")} covering ${plural(findingCount(plan), "finding")}`, "");
    plan.steps.forEach((s, i) => {
      lines.push(`${i + 1}. [${s.severityMax.toUpperCase()}] ${oneLine(s.title)}  (phase ${s.phase}: ${oneLine(s.phaseName)})`);
      lines.push(`   ${oneLine(s.summary)}`);
      if (s.files.length > 0) lines.push(`   files: ${s.files.map(oneLine).join(", ")}`);
      for (const c of s.commands ?? []) lines.push(`   run: ${oneLine(c)}`);
    });
  }
  if (plan.review.length > 0) {
    lines.push("", `${plural(plan.review.length, "finding")} need review first (low confidence or known): run \`whsquad fix --format triage\`.`);
  }
  if (plan.migrationSql) lines.push("", "Merged SQL migration:", "", stripControl(plan.migrationSql).trimEnd());
  return lines.join("\n") + "\n";
}
