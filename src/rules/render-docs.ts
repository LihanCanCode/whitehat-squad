import type { RuleMeta } from "./types.js";

const AGENT_NAMES: Readonly<Record<string, string>> = {
  recon: "Recon",
  "secrets-hunter": "SecretsHunter",
  "database-guard": "DatabaseGuard",
  "auth-auditor": "AuthAuditor",
  "web-hardener": "WebHardener",
  "supply-chain": "SupplyChain",
  "ai-guard": "AIGuard",
  "injection-hunter": "InjectionHunter",
  "py-guard": "PyGuard",
  "ai-review": "AI review (opt-in, whsquad review)",
};

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();

function ruleSection(r: RuleMeta): string {
  const refs = [r.cwe, r.owasp && `OWASP ${r.owasp}`].filter(Boolean).join(" · ");
  return [
    `### ${r.id}`,
    "",
    `**${r.title}** — ${r.severity}${refs ? ` · ${refs}` : ""} · modes: ${r.modes.join(", ")}`,
    "",
    r.summary.trim(),
    "",
    `**Fix:** ${r.fix.trim()}`,
    "",
  ].join("\n");
}

/**
 * docs/rules.md, generated from the catalog (`npx tsx scripts/gen-rules.ts`). A test fails when the
 * committed file drifts, so `ruleHelpUri` anchors (`#db-001`) always resolve.
 */
export function renderRulesDoc(rules: readonly RuleMeta[]): string {
  const agents = [...new Set(rules.map((r) => r.agent))];
  const out: string[] = [
    "# Rule reference",
    "",
    "<!-- Generated from src/rules/catalog.ts by scripts/gen-rules.ts. Do not edit by hand. -->",
    "",
    `${rules.length} deterministic rules across ${agents.length} agents. Every finding links here by id.`,
    "",
    "| Agent | Rules |",
    "| --- | --- |",
    ...agents.map((a) => {
      const ids = rules.filter((r) => r.agent === a).map((r) => `[${r.id}](#${r.id.toLowerCase()})`);
      return `| ${AGENT_NAMES[a] ?? a} | ${ids.join(" ")} |`;
    }),
    "",
  ];
  for (const a of agents) {
    out.push(`## ${AGENT_NAMES[a] ?? a}`, "", "| Id | Title | Severity |", "| --- | --- | --- |");
    const own = rules.filter((r) => r.agent === a);
    for (const r of own) out.push(`| [${r.id}](#${r.id.toLowerCase()}) | ${cell(r.title)} | ${r.severity} |`);
    out.push("", ...own.map(ruleSection));
  }
  return `${out.join("\n").trimEnd()}\n`;
}
