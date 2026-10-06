import { lineOf } from "../../core/source/index.js";
import { bareMatches, codeMatches, LLM_PKG } from "./context.js";
import type { Ctx, Hit } from "./context.js";

const SDK_IMPORT = new RegExp(
  `import\\s+(?!type\\b)[^;'"]*?from\\s*["'](?:${LLM_PKG})["']|require\\(\\s*["'](?:${LLM_PKG})["']\\s*\\)`,
);
const SDK_USE =
  /\bnew\s+(?:OpenAI|Anthropic|Groq|GoogleGenerativeAI|GoogleGenAI|Mistral|CohereClient)\s*\(|\b(?:createOpenAI|createAnthropic|createGoogleGenerativeAI|createGroq)\s*\(|\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\bgetGenerativeModel\s*\(/;
const BROWSER_FLAG = /\bdangerouslyAllowBrowser\s*:\s*true\b/;
const DIRECT_FETCH = /\b(?:fetch|axios(?:\s*\.\s*\w+)?)\s*\(\s*["'`]https?:\/\/api\.(?:openai|anthropic|groq)\.com/;
const AUTH_HEADER = /\bAuthorization\b|x-api-key|["']api-key["']/i;

/** AI-001: model provider SDK/API called from code that ships to the browser. */
export function detectClientLlm(c: Ctx): Hit[] {
  const critical = (index: number, variant: string): Hit[] => [{ ruleId: "AI-001", index, severity: "critical", confidence: "high", variant }];

  const flag = BROWSER_FLAG.exec(c.src.bare);
  if (flag && c.hasLlm) return critical(flag.index, "browser-flag");
  if (!c.isClient) return [];

  if (codeMatches(c.src, SDK_IMPORT).length > 0) {
    const use = bareMatches(c.src, SDK_USE)[0];
    if (use) return critical(use.index, "client-sdk");
  }
  for (const host of codeMatches(c.src, DIRECT_FETCH)) {
    if (AUTH_HEADER.test(c.src.code.slice(host.index, host.index + 800))) return critical(host.index, "client-fetch");
  }
  return [];
}

export const PUBLIC_KEY =
  /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|COHERE|REPLICATE|OPENROUTER|DEEPSEEK|XAI|TOGETHER)[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b/g;
const ENV_INDEX = /\benv\s*\??\.?\s*\[\s*["'`]$/;

/** AI-007: provider key read through a public env prefix (real code only: not comments, not other strings). */
export function detectPublicKeyVar(c: Ctx): Hit[] {
  if (/\.config\.[cm]?[jt]s$/.test(c.path)) return [];
  const hits: Hit[] = [];
  const seenLines = new Set<number>();
  for (const m of c.src.code.matchAll(PUBLIC_KEY)) {
    const inCode = c.src.bare.charAt(m.index) === c.src.code.charAt(m.index);
    const viaIndex = !inCode && ENV_INDEX.test(c.src.code.slice(Math.max(0, m.index - 24), m.index));
    if (!inCode && !viaIndex) continue;
    const line = lineOf(c.src, m.index);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    hits.push({
      ruleId: "AI-007",
      index: m.index,
      severity: c.isClient ? "critical" : "high",
      confidence: c.isClient ? "high" : "medium",
      variant: m[0],
    });
  }
  return hits;
}
