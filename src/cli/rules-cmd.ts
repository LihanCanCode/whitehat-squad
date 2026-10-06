import { ALL_RULES, ruleHelpUri, ruleMeta } from "../rules/catalog.js";
import type { RuleMeta } from "../rules/types.js";
import { UsageError } from "./args.js";

type Format = "json" | "terminal";

const asFormat = (format: string): Format => (format === "json" ? "json" : "terminal");

/** Rules for `whsquad rules [--agent X]`. */
export function selectRules(agent: string | undefined): readonly RuleMeta[] {
  if (agent === undefined) return ALL_RULES;
  const known = [...new Set(ALL_RULES.map((r) => r.agent))].sort();
  if (!known.includes(agent)) {
    throw new UsageError(`Unknown agent "${agent}". Agents with rules: ${known.join(", ")}.`);
  }
  return ALL_RULES.filter((r) => r.agent === agent);
}

const withLink = (r: RuleMeta): RuleMeta & { readonly helpUri: string } => ({ ...r, helpUri: ruleHelpUri(r.id) });

export function renderRules(rules: readonly RuleMeta[], format: string): string {
  if (asFormat(format) === "json") return JSON.stringify(rules.map(withLink), null, 2) + "\n";
  if (rules.length === 0) return "No rules match.\n";
  const idWidth = Math.max(4, ...rules.map((r) => r.id.length));
  const sevWidth = 8;
  const agentWidth = Math.max(5, ...rules.map((r) => r.agent.length));
  const row = (id: string, sev: string, agent: string, title: string): string =>
    `${id.padEnd(idWidth)}  ${sev.padEnd(sevWidth)}  ${agent.padEnd(agentWidth)}  ${title}`;
  return [row("RULE", "SEVERITY", "AGENT", "TITLE"), ...rules.map((r) => row(r.id, r.severity, r.agent, r.title))].join("\n") + "\n";
}

/** Looks a rule up by id (any case); unknown ids get a UsageError with the closest matches. */
export function findRule(id: string): RuleMeta {
  const hit = ruleMeta(id.toUpperCase());
  if (hit) return hit;
  const family = id.toUpperCase().split("-")[0] ?? "";
  const near = ALL_RULES.filter((r) => r.id.startsWith(`${family}-`)).map((r) => r.id).slice(0, 8);
  throw new UsageError(
    `Unknown rule "${id}".` +
      (near.length > 0 ? ` Did you mean: ${near.join(", ")}?` : "") +
      ' Run "whsquad rules" to list every rule.',
  );
}

export function renderExplain(rule: RuleMeta, format: string): string {
  if (asFormat(format) === "json") return JSON.stringify(withLink(rule), null, 2) + "\n";
  const lines = [
    `${rule.id}  ${rule.title}`,
    `Severity: ${rule.severity} (default)   Agent: ${rule.agent}   Scans: ${rule.modes.join(", ")}`,
    ...(rule.cwe || rule.owasp ? [`References: ${[rule.cwe, rule.owasp ? `OWASP ${rule.owasp}` : undefined].filter(Boolean).join(", ")}`] : []),
    "",
    "What it detects",
    `  ${rule.summary}`,
    "",
    "How to fix",
    `  ${rule.fix}`,
    "",
    `Docs: ${ruleHelpUri(rule.id)}`,
    `Suppress one reviewed finding: // whsquad-ignore ${rule.id} -- reason`,
  ];
  return lines.join("\n") + "\n";
}
