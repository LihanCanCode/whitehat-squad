import { exprEnd, matchClose } from "../../core/source/index.js";
import { skipTemplate } from "../../core/source/scan.js";
import { codeMatches, isFromSource, requestTaint, scopeAt } from "./context.js";
import type { Ctx, Hit } from "./context.js";

const SYSTEM_ANCHORS: readonly RegExp[] = [
  /\b(?:system|systemInstruction|system_instruction|instructions)\s*:\s*/g,
  /\brole\s*:\s*["'](?:system|developer)["']\s*,\s*content\s*:\s*/g,
  /\b(?:const|let|var)\s+(?:systemPrompt|system_prompt|SYSTEM_PROMPT|systemMessage|systemInstructions?)\s*(?::[^=\n]+)?=\s*/g,
  /\[\s*["'](?:system|developer)["']\s*,\s*/g,
];
const CALL_HEAD = /^\s*[A-Za-z_$][\w$.]*\s*\(/;

/** AI-002: request-controlled text reaches a system/developer prompt. */
export function detectSystemPromptInjection(c: Ctx): Hit[] {
  const { src } = c;
  const hits: Hit[] = [];
  const seen = new Set<number>();
  for (const anchor of SYSTEM_ANCHORS) {
    for (const m of codeMatches(src, anchor)) {
      if (seen.has(m.index)) continue;
      const pos = m.index + m[0].length;
      const end = exprEnd(src, pos, true);
      const text = src.code.slice(pos, end);
      const taint = requestTaint(c, scopeAt(c, m.index));
      let confidence: "high" | "low" | undefined;
      if (taint.isTainted(text, m.index)) confidence = "high";
      else if (CALL_HEAD.test(text)) {
        // A helper such as systemPrompt({ hints }) may sanitize; we cannot see inside it.
        const open = pos + text.indexOf("(");
        const close = matchClose(src, open);
        if (close > 0 && taint.isTainted(src.code.slice(open + 1, close - 1), m.index)) confidence = "low";
      }
      if (!confidence) continue;
      seen.add(m.index);
      hits.push({ ruleId: "AI-002", index: m.index, severity: "high", confidence });
    }
  }
  return hits;
}

const TOOLS_ENABLED =
  /\btools\s*[:,}]|\bfunctions\s*:|\btool_choice\b|\btoolChoice\b|\bmaxSteps\b|\bstopWhen\b|\bfunction_call\b|\bbindTools\b|\bcreateReactAgent\b|\bAgentExecutor\b/;
/** Matched against neutralised (strings and call arguments blanked) right-hand sides. */
const UNTRUSTED_SOURCES: readonly RegExp[] = [
  /(?<![\w$.])(?:fetch|axios|firecrawl\w*|tavily\w*|cheerio|scrape\w*|crawl\w*|retriev\w*|similaritySearch|vectorStore|searchResults?)\b/i,
  /\.\s*(?:text|findMany|findFirst|select|similaritySearch|scrape\w*|crawl\w*)\s*\(/,
  /\bdb\s*\.\s*(?:select|query)\b/,
  /\breadFile(?:Sync)?\b/,
];
const PROMPT_SLOT = /(?:content|prompt|system|text|input|instructions?|message|context)\w*\s*[:=(]\s*$/i;
const DELIMITER = /<\/?[A-Za-z_][\w-]*>|untrusted|"""|-{3,}|={3,}|\bBEGIN\b|delimit/i;

interface Tpl {
  readonly start: number;
  readonly end: number;
  readonly text: string;
  readonly exprs: readonly string[];
}

/** Top-level template literals with their literal text and `${}` expressions (bare view of the expressions). */
function templates(c: Ctx): Tpl[] {
  const { src } = c;
  const out: Tpl[] = [];
  let i = 0;
  while (i < src.bare.length) {
    if (src.bare.charAt(i) !== "`") {
      i++;
      continue;
    }
    const end = skipTemplate(src, i);
    const lit: string[] = [];
    const exprs: string[] = [];
    for (let j = i + 1; j < end - 1; j++) {
      if (src.bare.charAt(j) === "$" && src.bare.charAt(j + 1) === "{") {
        const close = matchClose(src, j + 1);
        if (close < 0) break;
        exprs.push(src.bare.slice(j + 2, close - 1));
        j = close - 1;
      } else lit.push(src.code.charAt(j));
    }
    out.push({ start: i, end, text: lit.join(""), exprs });
    i = end;
  }
  return out;
}

/** AI-006: fetched / retrieved / stored content pasted undelimited into a prompt of a tool-enabled call. */
export function detectIndirectInjection(c: Ctx): Hit[] {
  if (!c.hasLlm) return [];
  const hits: Hit[] = [];
  for (const t of templates(c)) {
    const slot = c.src.code.slice(Math.max(0, t.start - 60), t.start);
    if (!PROMPT_SLOT.test(slot) || DELIMITER.test(t.text)) continue;
    const scope = scopeAt(c, t.start);
    if (!TOOLS_ENABLED.test(c.src.bare.slice(scope.start, scope.end))) continue;
    if (t.exprs.some((e) => isFromSource(c, scope, "untrusted", UNTRUSTED_SOURCES, e, t.start))) {
      hits.push({ ruleId: "AI-006", index: t.start, severity: "medium", confidence: "low" });
    }
  }
  return hits;
}
