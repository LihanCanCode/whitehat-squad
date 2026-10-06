import { analyzeTaint, classifyFile, createSource, findUnits, handlerUnits, parseParams } from "../../core/source/index.js";
import type { FileKind, FunctionUnit, Source, TaintAnalysis } from "../../core/source/index.js";
import type { Confidence, Severity } from "../../core/types.js";

export type RuleId = "AI-001" | "AI-002" | "AI-003" | "AI-004" | "AI-005" | "AI-006" | "AI-007" | "AI-008" | "AI-009" | "AI-010";

export interface Hit {
  readonly ruleId: RuleId;
  /** Offset into the file (all views share offsets). */
  readonly index: number;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Rule-specific sub-type that selects explanation wording. */
  readonly variant?: string;
}

export interface ProjectEnv {
  readonly viteLike: boolean;
  /** middleware.* in the project mentions auth or rate limiting. */
  readonly middlewareProtected: boolean;
  /** The project depends on an auth library (per-user data is plausible). */
  readonly hasUserAuth: boolean;
}

export const LLM_PKG =
  "openai|@anthropic-ai/sdk|@google/generative-ai|@google/genai|groq-sdk|@mistralai/mistralai|cohere-ai|@ai-sdk/(?:openai|anthropic|google|groq|mistral)";
const LLM_IMPORT = new RegExp(`(?:from\\s*|require\\(\\s*|import\\(\\s*)["'](?:${LLM_PKG}|ai|@langchain/[\\w-]+|langchain|ollama|replicate|together-ai)["']`);
const LLM_HOST = /api\.openai\.com|api\.anthropic\.com|api\.groq\.com|openrouter\.ai\/api|generativelanguage\.googleapis\.com/;

export interface Ctx {
  readonly path: string;
  readonly src: Source;
  readonly env: ProjectEnv;
  readonly kind: FileKind;
  readonly isClient: boolean;
  readonly hasLlm: boolean;
  readonly units: readonly FunctionUnit[];
  readonly handlers: readonly FunctionUnit[];
  readonly moduleUnit: FunctionUnit;
  readonly cache: Map<string, TaintAnalysis>;
}

export function buildCtx(path: string, raw: string, env: ProjectEnv): Ctx {
  const src = createSource(path, raw);
  const kind = classifyFile(src, { clientTree: env.viteLike });
  const moduleUnit: FunctionUnit = { name: "<module>", kind: "function", exported: false, start: 0, end: raw.length, bodyStart: 0, params: "" };
  return {
    path,
    src,
    env,
    kind,
    isClient: kind === "client",
    hasLlm: LLM_IMPORT.test(src.code) || LLM_HOST.test(src.code),
    units: findUnits(src),
    handlers: handlerUnits(src),
    moduleUnit,
    cache: new Map(),
  };
}

/** Matches on `code` (strings kept) whose first character is real code (not in a comment, string or regex). */
export function codeMatches(src: Source, re: RegExp): RegExpExecArray[] {
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const out: RegExpExecArray[] = [];
  for (let m = rx.exec(src.code); m; m = rx.exec(src.code)) {
    if (m[0].length === 0) {
      rx.lastIndex++;
      continue;
    }
    if (src.bare.charAt(m.index) === src.code.charAt(m.index)) out.push(m);
  }
  return out;
}

export function bareMatches(src: Source, re: RegExp): RegExpExecArray[] {
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  return [...src.bare.matchAll(rx)];
}

/** Innermost request-handling unit containing `offset`. */
export function handlerAt(c: Ctx, offset: number): FunctionUnit | undefined {
  let best: FunctionUnit | undefined;
  for (const u of c.handlers) {
    if (offset < u.start || offset >= u.end) continue;
    if (!best || u.end - u.start < best.end - best.start) best = u;
  }
  return best;
}

/** Analysis scope for `offset`: its handler, else the outermost function, else the module. */
export function scopeAt(c: Ctx, offset: number): FunctionUnit {
  const handler = handlerAt(c, offset);
  if (handler) return handler;
  let best: FunctionUnit | undefined;
  for (const u of c.units) {
    if (offset < u.start || offset >= u.end) continue;
    if (!best || u.end - u.start > best.end - best.start) best = u;
  }
  return best ?? c.moduleUnit;
}

const REQUEST_LIKE_PARAM = /^(?:req|request|ctx|event|formData)$/;

function cached(c: Ctx, key: string, make: () => TaintAnalysis): TaintAnalysis {
  const hit = c.cache.get(key);
  if (hit) return hit;
  const made = make();
  c.cache.set(key, made);
  return made;
}

const unitKey = (u: FunctionUnit, tag: string): string => `${tag}:${u.start}:${u.end}`;

/** Request taint for a unit (non-handler functions also treat `req`-like parameters as request data). */
export function requestTaint(c: Ctx, unit: FunctionUnit): TaintAnalysis {
  return cached(c, unitKey(unit, "req"), () => {
    const names = unit.role || unit.action ? [] : parseParams(unit.params).flatMap((p) => p.names).filter((n) => REQUEST_LIKE_PARAM.test(n));
    return analyzeTaint(c.src, unit, { taintedNames: names });
  });
}

/** Taint from a custom set of sources (model output, fetched content); no parameter seeding. */
export function sourceTaint(c: Ctx, unit: FunctionUnit, tag: string, sources: readonly RegExp[]): TaintAnalysis {
  return cached(c, unitKey(unit, tag), () => analyzeTaint(c.src, unit, { extraSources: sources, seedParams: false }));
}

const IDENT = /(?<![\w$.])[A-Za-z_$][\w$]*/g;

/** Identifiers used as values in a bare expression (property names and object keys excluded). */
export function identsOf(bare: string): string[] {
  const out: string[] = [];
  for (const m of bare.matchAll(IDENT)) {
    const after = bare.slice(m.index + m[0].length, m.index + m[0].length + 4);
    let k = m.index;
    while (k > 0 && /\s/.test(bare.charAt(k - 1))) k--;
    const before = bare.charAt(k - 1);
    if (/^\s*:(?!:)/.test(after) && (before === "{" || before === ",")) continue;
    out.push(m[0]);
  }
  return out;
}

/**
 * Is `exprBare` (a bare-view expression) data from `analysis` but NOT plain request data?
 * Used to tell model output / fetched content apart from the user's own input.
 */
export function isFromSource(
  c: Ctx,
  unit: FunctionUnit,
  tag: string,
  sources: readonly RegExp[],
  exprBare: string,
  at: number,
): boolean {
  if (sources.some((r) => new RegExp(r.source, r.flags.replace("g", "")).test(exprBare))) return true;
  const mine = sourceTaint(c, unit, tag, sources).taintedNames(at);
  if (mine.size === 0) return false;
  const request = requestTaint(c, unit).taintedNames(at);
  return identsOf(exprBare).some((n) => mine.has(n) && !request.has(n));
}

/** Bare text of `[from, to)`. */
export const bareSlice = (c: Ctx, from: number, to: number): string => c.src.bare.slice(from, to);
