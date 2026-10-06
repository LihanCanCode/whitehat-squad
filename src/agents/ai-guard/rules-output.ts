import { exprEnd, matchClose, splitArgs } from "../../core/source/index.js";
import type { Confidence, Severity } from "../../core/types.js";
import { bareMatches, identsOf, isFromSource, scopeAt } from "./context.js";
import type { Ctx, Hit } from "./context.js";

/**
 * Shapes of "this value came out of a model". Deliberately NOT `message.content` / `m.content`: those are
 * overwhelmingly the user's own chat messages (`messages.map((m) => m.content)`), not model output. A
 * model message is still caught when it is derived from one of the shapes below.
 */
export const OUTPUT_SEEDS: readonly RegExp[] = [
  /choices\s*\[\s*0\s*\]\s*\??\.\s*(?:message|text|delta)\b/,
  /\.content\s*\[\s*0\s*\]\s*\??\.text/,
  /\.output_text\b/,
  /\.response\.text\b/,
  /\b(?:completion|response)\.content\b/,
  /\bcompletion\.text\b/,
  /\b(?:generateText|streamText|generateObject)\b(?=\s*\()/,
  /\btool_calls\b|\btoolCalls\b/,
  /\b\w*[cC]all\w*(?:\??\.function)?\??\.name\b/,
];
const TOOL_GUARD = /\b(?:allowed\w*|ALLOWED\w*|allowlist|whitelist|ALLOWLIST)\b|\bhasOwn(?:Property)?\b|\b\w*[nN]ame\s+in\s+\w+/;

interface SinkSpec {
  readonly re: RegExp;
  readonly variant: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** args: every call argument, first: first argument only, expr: expression after the match. */
  readonly mode: "args" | "first" | "expr";
}

const SINKS: readonly SinkSpec[] = [
  { re: /(?<![.\w$])eval\s*\(/g, variant: "eval", severity: "critical", confidence: "high", mode: "args" },
  { re: /\bnew\s+Function\s*\(/g, variant: "eval", severity: "critical", confidence: "high", mode: "args" },
  { re: /\bvm\.(?:runIn\w+|Script)\s*\(|\brunInNewContext\s*\(/g, variant: "eval", severity: "critical", confidence: "high", mode: "args" },
  {
    re: /(?<![.\w$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\b(?:child_process|cp|childProcess)\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/g,
    variant: "exec", severity: "critical", confidence: "high", mode: "args",
  },
  { re: /\.(?:query|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(|(?<!\bString)\.raw\s*\(|\bsql\.raw\s*\(/g, variant: "sql", severity: "high", confidence: "medium", mode: "first" },
  { re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*/g, variant: "html", severity: "high", confidence: "high", mode: "expr" },
  { re: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*/g, variant: "html", severity: "high", confidence: "high", mode: "expr" },
  { re: /\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(/g, variant: "html", severity: "high", confidence: "high", mode: "args" },
  { re: /(?<![.\w$])(?:import|require)\s*\(/g, variant: "import", severity: "high", confidence: "medium", mode: "first" },
];

/** Bare text of the sink's relevant expressions. */
function sinkTexts(c: Ctx, spec: SinkSpec, end: number): string[] {
  const { src } = c;
  if (spec.mode === "expr") return [src.bare.slice(end, exprEnd(src, end, true))];
  const open = end - 1;
  const close = matchClose(src, open);
  if (close < 0) return [];
  const args = splitArgs(src, open + 1, close - 1).map((a) => src.bare.slice(a.start, a.end));
  return spec.mode === "first" ? args.slice(0, 1) : args;
}

/** AI-003: model output reaches an execution, query, markup or dispatch sink. */
export function detectUnsafeOutput(c: Ctx): Hit[] {
  if (!c.hasLlm) return [];
  const hits: Hit[] = [];
  const isOut = (text: string, at: number): boolean => isFromSource(c, scopeAt(c, at), "output", OUTPUT_SEEDS, text, at);

  for (const s of SINKS) {
    for (const m of bareMatches(c.src, s.re)) {
      const end = m.index + m[0].length;
      if (sinkTexts(c, s, end).some((t) => isOut(t, m.index))) {
        hits.push({ ruleId: "AI-003", index: m.index, severity: s.severity, confidence: s.confidence, variant: s.variant });
      }
    }
  }

  for (const m of bareMatches(c.src, /\b[A-Za-z_$][\w$]*\s*\[\s*([^\]\n]+?)\s*\]\s*\(/g)) {
    const key = m[1] ?? "";
    const scope = scopeAt(c, m.index);
    if (/^\d+$/.test(key) || TOOL_GUARD.test(c.src.bare.slice(scope.start, scope.end))) continue;
    if (identsOf(key).length > 0 && isOut(key, m.index)) {
      hits.push({ ruleId: "AI-003", index: m.index, severity: "high", confidence: "medium", variant: "tool" });
    }
  }
  return hits;
}
