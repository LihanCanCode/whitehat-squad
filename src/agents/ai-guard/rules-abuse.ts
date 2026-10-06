import { matchClose, splitArgs, unitHas } from "../../core/source/index.js";
import type { FunctionUnit } from "../../core/source/index.js";
import { bareMatches, codeMatches, handlerAt, requestTaint, scopeAt } from "./context.js";
import type { Ctx, Hit, ProjectEnv } from "./context.js";

const SDK_CALL =
  /\.chat\.completions\.create\s*\(|\.completions\.create\s*\(|\.messages\.(?:create|stream)\s*\(|\.responses\.(?:create|stream)\s*\(|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|\.generateContent(?:Stream)?\s*\(/;
const HOST_CALL = /\bfetch\s*\(\s*["'`]https?:\/\/(?:api\.(?:openai|anthropic|groq)\.com|openrouter\.ai\/api|generativelanguage\.googleapis\.com)/;

const MAX_TOKENS =
  /\b(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens|maxCompletionTokens|max_tokens_to_sample|num_predict)\b/;
const INPUT_CAP =
  /\.slice\(\s*0|\.substring\(|\.substr\(|\.length\s*(?:>=?|<=?)|\.max\(\s*[\w.]+|\bmaxLength\b|\bMAX_[A-Z_]*(?:LEN|CHARS|INPUT|LENGTH)\b|\btruncate\w*\(/;

export interface LlmCall {
  /** Offset of the call (start of the matched callee). */
  readonly index: number;
  /** Offset of the opening parenthesis. */
  readonly open: number;
}

/** Every model call in the file: SDK shapes on the bare view, raw provider fetches on the code view. */
export function llmCalls(c: Ctx): LlmCall[] {
  if (!c.hasLlm) return [];
  const calls: LlmCall[] = [];
  for (const m of bareMatches(c.src, new RegExp(SDK_CALL.source, "g"))) calls.push({ index: m.index, open: m.index + m[0].length - 1 });
  for (const m of codeMatches(c.src, HOST_CALL)) calls.push({ index: m.index, open: c.src.code.indexOf("(", m.index) });
  return calls.sort((a, b) => a.index - b.index);
}

/** The text of the call's arguments (code view, so keys such as max_tokens stay visible). */
function argsCode(c: Ctx, call: LlmCall): string {
  const close = matchClose(c.src, call.open);
  return close < 0 ? "" : c.src.code.slice(call.open + 1, close - 1);
}

function nameCalledIn(c: Ctx, handler: FunctionUnit, name: string): boolean {
  if (name === "" || name === "default") return false;
  return new RegExp(`(?<![\\w$.])${name.replace(/\$/g, "\\$")}\\s*\\(`).test(c.src.bare.slice(handler.start, handler.end));
}

/** Handlers that run this call: the handler containing it, or handlers calling the local helper containing it. */
function handlersFor(c: Ctx, call: LlmCall): FunctionUnit[] {
  const own = handlerAt(c, call.index);
  if (own) return [own];
  let helper: FunctionUnit | undefined;
  for (const u of c.units) {
    if (call.index < u.start || call.index >= u.end || u.role) continue;
    if (!helper || u.end - u.start < helper.end - helper.start) helper = u;
  }
  return helper ? c.handlers.filter((h) => nameCalledIn(c, h, helper.name)) : [];
}

/** AI-004: public route/action that spends model credits with neither auth nor rate limiting (checked per handler). */
export function detectUnprotectedRoute(c: Ctx, env: ProjectEnv): Hit[] {
  if (c.isClient || c.handlers.length === 0) return [];
  const firstCall = new Map<FunctionUnit, LlmCall>();
  for (const call of llmCalls(c)) {
    for (const h of handlersFor(c, call)) if (!firstCall.has(h)) firstCall.set(h, call);
  }
  const hits: Hit[] = [];
  for (const [handler, call] of firstCall) {
    if (handler.role === "middleware") continue;
    const opts = { includeRouterMiddleware: true };
    if (unitHas(c.src, handler, "auth", opts) || unitHas(c.src, handler, "rateLimit", opts)) continue;
    hits.push({ ruleId: "AI-004", index: call.index, severity: "high", confidence: env.middlewareProtected ? "low" : "medium" });
  }
  return hits;
}

const REQ_FIRST_PARAM = /^\s*(?:req|request)\b/;

/**
 * The call sits in a local helper (generateWithFallback(prompt)) that a controller-style function
 * (first parameter req/request, registered elsewhere) calls with request-derived arguments.
 */
function fedByCaller(c: Ctx, call: LlmCall, helper: FunctionUnit): FunctionUnit | undefined {
  if (helper.name === "" || helper.name === "<module>" || helper.name === "default") return undefined;
  const re = new RegExp(String.raw`(?<![\w$.])${helper.name.replace(/\$/g, String.raw`\$`)}\s*\(`, "g");
  for (const caller of c.units) {
    if (caller === helper || !REQ_FIRST_PARAM.test(caller.params)) continue;
    if (call.index >= caller.start && call.index < caller.end) continue;
    const body = c.src.bare.slice(caller.start, caller.end);
    for (const m of body.matchAll(re)) {
      const open = caller.start + m.index + m[0].length - 1;
      const close = matchClose(c.src, open);
      if (close < 0) continue;
      if (requestTaint(c, caller).isTainted(c.src.code.slice(open + 1, close - 1), open)) return caller;
    }
  }
  return undefined;
}

/** AI-005: no output cap and no input cap on user-supplied text, judged per model call and its own unit. */
export function detectUnboundedUsage(c: Ctx): Hit[] {
  const hits: Hit[] = [];
  const capped = new Map<string, boolean>();
  for (const call of llmCalls(c)) {
    const scope = scopeAt(c, call.index);
    const args = argsCode(c, call);
    if (MAX_TOKENS.test(args)) continue;
    // A pre-built options object (create(params), create({ ...base })) may carry the cap elsewhere.
    const opaque = /^\s*[\w$.]*\s*$/.test(args) || args.includes("...");
    if (opaque && MAX_TOKENS.test(c.src.bare)) continue;
    const key = `${scope.start}:${scope.end}`;
    if (!capped.has(key)) capped.set(key, INPUT_CAP.test(c.src.bare.slice(scope.start, scope.end)));
    if (capped.get(key)) continue;
    const caller = requestTaint(c, scope).isTainted(args, call.index) ? undefined : fedByCaller(c, call, scope);
    if (!caller && !requestTaint(c, scope).isTainted(args, call.index)) continue;
    if (caller && INPUT_CAP.test(c.src.bare.slice(caller.start, caller.end))) continue;
    hits.push({ ruleId: "AI-005", index: call.index, severity: "medium", confidence: "medium" });
  }
  return hits;
}

// ---------------------------------------------------------------------------------------------
// AI-010: tool/agent loops without a step cap

const STEP_LIMIT = 20;
const LOOP_HEAD = /\bwhile\s*\(\s*(?:true|1|!0)\s*\)\s*\{|\bfor\s*\(\s*;\s*;\s*\)\s*\{/g;
const COUNTER =
  /\b(?:step|steps|iteration|iterations|turn|turns|round|rounds|attempt|attempts|depth|loops?)\w*\s*(?:\+\+|\+=|[<>]=?)|(?:\+\+|--)\s*(?:step|steps|iteration|iterations|turn|turns|round|rounds|attempt|attempts|depth)\w*|\bMAX_\w*(?:STEPS|ITER\w*|TURNS|ROUNDS|DEPTH)\b|\bmax(?:Steps|Iterations|Turns|Rounds|Depth)\b/i;

function inLoop(c: Ctx, offset: number): boolean {
  const b = c.src.bare;
  for (const m of b.matchAll(LOOP_HEAD)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(c.src, open);
    if (close > 0 && offset > open && offset < close) return true;
  }
  return false;
}

function isRecursive(c: Ctx, offset: number): boolean {
  let fn: FunctionUnit | undefined;
  for (const u of c.units) {
    if (offset < u.start || offset >= u.end || u.role || u.name === "" || u.name === "default") continue;
    if (!fn || u.end - u.start < fn.end - fn.start) fn = u;
  }
  if (!fn) return false;
  const body = c.src.bare.slice(fn.bodyStart + 1, fn.end);
  return new RegExp(`(?<![\\w$.])${fn.name.replace(/\$/g, "\\$")}\\s*\\(`).test(body);
}

function stepLimitOf(args: string): number | "none" {
  const steps = /\bmaxSteps\s*:\s*(\d+)/.exec(args) ?? /\bstepCountIs\s*\(\s*(\d+)\s*\)/.exec(args);
  return steps?.[1] ? Number(steps[1]) : "none";
}

/** AI-010: an agent loop (maxSteps / stopWhen too high, or an unbounded loop around a tool-enabled call). */
export function detectUncappedAgentLoop(c: Ctx): Hit[] {
  const hits: Hit[] = [];
  for (const call of llmCalls(c)) {
    const args = argsCode(c, call);
    if (!/\btools\s*[:,}]|\bfunctions\s*:|\bmaxSteps\b|\bstopWhen\b/.test(args)) continue;
    const limit = stepLimitOf(args);
    if (limit !== "none") {
      if (limit > STEP_LIMIT) hits.push({ ruleId: "AI-010", index: call.index, severity: "low", confidence: "high", variant: String(limit) });
      continue;
    }
    if (!/\btools\s*[:,}]|\bfunctions\s*:/.test(args)) continue;
    const scope = scopeAt(c, call.index);
    if (COUNTER.test(c.src.bare.slice(scope.start, scope.end))) continue;
    if (inLoop(c, call.index) || isRecursive(c, call.index)) {
      hits.push({ ruleId: "AI-010", index: call.index, severity: "low", confidence: "medium", variant: "loop" });
    }
  }
  return hits;
}

/** Split of top-level argument spans of a call (re-exported for the tool rules). */
export function callArgSpans(c: Ctx, open: number): { start: number; end: number }[] {
  const close = matchClose(c.src, open);
  return close < 0 ? [] : splitArgs(c.src, open + 1, close - 1).map((s) => ({ start: s.start, end: s.end }));
}
