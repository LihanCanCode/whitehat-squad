import { makeFinding } from "../../core/finding.js";
import type { Finding } from "../../core/types.js";
import { CORE_DOCS, type Doc } from "./docs-core.js";
import { NEW_DOCS } from "./docs-new.js";
import type { Raised } from "./report-types.js";
import { RULES } from "./rules.meta.js";
import { AGENT_ID } from "./util.js";

export type { Raised } from "./report-types.js";

const DOCS: Readonly<Record<string, Doc>> = { ...CORE_DOCS, ...NEW_DOCS };

/** Documentation for a rule: the variant, else the plain rule, else any variant, else the catalog entry. Never throws. */
export function docFor(raised: Pick<Raised, "ruleId" | "variant">): Doc {
  const exact = raised.variant ? DOCS[`${raised.ruleId}:${raised.variant}`] : undefined;
  if (exact) return exact;
  const plain = DOCS[raised.ruleId];
  if (plain) return plain;
  const anyVariant = Object.entries(DOCS).find(([key]) => key.startsWith(`${raised.ruleId}:`));
  if (anyVariant) return anyVariant[1];
  const meta = RULES.find((r) => r.id === raised.ruleId);
  return {
    title: meta?.title ?? `Authentication issue (${raised.ruleId})`,
    severity: meta?.severity ?? "medium",
    cwe: meta?.cwe ?? "CWE-287",
    explanation: meta?.summary ?? "This code has an authentication or authorization weakness.",
    summary: meta?.fix ?? "Review the flagged code and enforce authentication and authorization on the server.",
    snippet: "// see the rule catalog entry for guidance",
    instruction: "review this code for the weakness described above and enforce the check on the server.",
    refs: [],
  };
}

export function toFinding(raised: Raised): Finding {
  const doc = docFor(raised);
  const where = `${raised.file}:${raised.line}`;
  const explanation = raised.note ? `${doc.explanation} ${raised.note}` : doc.explanation;
  return makeFinding({
    ruleId: raised.ruleId,
    agentId: AGENT_ID,
    title: doc.title,
    severity: doc.severity,
    confidence: raised.confidence ?? "high",
    explanation,
    evidence: [{ file: raised.file, line: raised.line, snippet: raised.snippet }],
    cwe: doc.cwe,
    target: raised.file,
    fix: {
      summary: doc.summary,
      config: doc.snippet,
      patch: { file: raised.file, diff: doc.snippet },
      agentPrompt: `In ${raised.file} at line ${raised.line} (${where}), ${doc.instruction} Show the exact diff, keep behaviour otherwise unchanged, and re-run \`whsquad verify ${raised.ruleId} ${raised.file}\`.`,
      references: doc.refs,
    },
  });
}
