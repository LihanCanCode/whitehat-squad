import { analyzeTaint, exprEnd, unitHas, type FunctionUnit, type TaintAnalysis } from "../../core/source/index.js";
import { argText, findCalls, fullInitializer, outermostUnit, type Call } from "./calls.js";
import type { FileCtx, Project } from "./context.js";
import type { Raised } from "./report-types.js";
import { targetKey } from "./sensitive.js";
import { codeMatches, hasCode, makeHit } from "./util.js";

interface Sink {
  readonly index: number;
  /** Expression passed whole to the write. */
  readonly value: string;
  readonly at: number;
  readonly target: string | undefined;
}

const NOT_MODELS = new Set(["URL", "Request", "Response", "Headers", "Error", "Date", "Map", "Set", "FormData", "URLSearchParams", "Promise", "RegExp", "Array", "Buffer", "TextEncoder", "TextDecoder", "Blob", "File", "Object", "String", "Number"]);
const PRISMA_WRITE = /\.\s*(?:create|createMany|update|updateMany|upsert)\s*\(/;
const MONGO_UPDATE = /\.\s*(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|replaceOne|findOneAndReplace)\s*\(/;
const MONGO_CREATE = /\.\s*(?:create|insertMany|insertOne)\s*\(/;
const SQL_BUILDER = /\.\s*(?:values|set)\s*\(/;
const SUPABASE_WRITE = /\.\s*(?:insert|update|upsert)\s*\(/;

function receiverBefore(code: string, index: number): string {
  return /([\w$.]+(?:\([^()]*\))?)\s*$/.exec(code.slice(Math.max(0, index - 80), index))?.[1] ?? "";
}

function stripArray(text: string): string {
  const t = text.trim();
  return t.startsWith("[") && t.endsWith("]") ? t.slice(1, -1).trim() : t;
}

/** The value expression of `key:` (or shorthand `key`) inside an object-literal argument. */
function keyValue(f: FileCtx, call: Call, key: string): { text: string; at: number } | undefined {
  const { src } = f;
  const re = new RegExp(String.raw`(?<![\w$.])${key}\s*:\s*`, "g");
  const m = codeMatches(src, re, call.open, call.close)[0];
  if (m) {
    const from = m.index + m[0].length;
    return { text: src.code.slice(from, exprEnd(src, from, true)), at: from };
  }
  const short = codeMatches(src, new RegExp(String.raw`[{,]\s*${key}\s*(?=[,}])`), call.open, call.close)[0];
  return short ? { text: key, at: short.index } : undefined;
}

function prismaSinks(f: FileCtx): Sink[] {
  const out: Sink[] = [];
  for (const call of findCalls(f.src, PRISMA_WRITE)) {
    if (!argText(f.src, call, 0).startsWith("{")) continue;
    const recv = receiverBefore(f.src.code, call.index).split(".");
    for (const key of ["data", "create", "update"]) {
      const v = keyValue(f, call, key);
      if (v) out.push({ index: call.index, value: v.text, at: v.at, target: recv[recv.length - 1] });
    }
  }
  return out;
}

function builderSinks(f: FileCtx): Sink[] {
  const { src } = f;
  const out: Sink[] = [];
  for (const call of findCalls(src, SQL_BUILDER)) {
    const before = src.code.slice(Math.max(0, call.index - 200), call.index);
    const target = /\.\s*(?:insert|update)\s*\(\s*([\w$]+)\s*\)[^;]*$/.exec(before)?.[1];
    out.push({ index: call.index, value: stripArray(argText(src, call, 0)), at: call.open, target });
  }
  for (const call of findCalls(src, SUPABASE_WRITE)) {
    const before = src.code.slice(Math.max(0, call.index - 200), call.index);
    const from = /\.\s*from\s*\(\s*["'`]([\w.]+)["'`]\s*\)[^;]*$/.exec(before);
    if (from) out.push({ index: call.index, value: stripArray(argText(src, call, 0)), at: call.open, target: from[1] });
  }
  return out;
}

function mongoSinks(f: FileCtx): Sink[] {
  const { src } = f;
  const out: Sink[] = [];
  for (const call of findCalls(src, MONGO_UPDATE)) {
    const second = argText(src, call, 1);
    const set = /^\{\s*\$set\s*:\s*([\s\S]*?)\s*\}$/.exec(second);
    out.push({ index: call.index, value: set?.[1] ?? second, at: call.open, target: receiverBefore(src.code, call.index).split(".").pop() });
  }
  for (const call of findCalls(src, MONGO_CREATE)) {
    const recv = receiverBefore(src.code, call.index);
    const model = recv.split(".").pop() ?? "";
    if (!/^[A-Z]\w*$|Model$|^collection$/.test(model) || NOT_MODELS.has(model)) continue;
    out.push({ index: call.index, value: stripArray(argText(src, call, 0)), at: call.open, target: model });
  }
  for (const call of findCalls(src, /\bnew\s+([A-Z]\w*)\s*\(/)) {
    const name = /new\s+([A-Z]\w*)/.exec(src.code.slice(call.index, call.open))?.[1] ?? "";
    if (NOT_MODELS.has(name) || !hasCode(src, /\.\s*save\s*\(/)) continue;
    out.push({ index: call.index, value: argText(src, call, 0), at: call.open, target: name });
  }
  return out;
}

function assignSinks(f: FileCtx): Sink[] {
  const { src } = f;
  const out: Sink[] = [];
  for (const call of findCalls(src, /\bObject\s*\.\s*assign\s*\(/)) {
    const target = argText(src, call, 0);
    if (target.startsWith("{") || !/^[\w$.]+$/.test(target)) continue;
    if (!hasCode(src, /\.\s*(?:save|update|create|insert|upsert|persist)\s*\(/)) continue;
    out.push({ index: call.index, value: argText(src, call, 1), at: call.open, target });
  }
  return out;
}

/** A value that carries the request body whole (identifier, `await req.json()`, or an object spreading it). */
function wholeTainted(f: FileCtx, text: string, at: number, taint: TaintAnalysis): boolean {
  let t = text.trim();
  if (t === "") return false;
  if (/^[A-Za-z_$][\w$]*$/.test(t)) {
    // A local object literal built from named fields is an explicit pick, not the body itself.
    const init = fullInitializer(f.src, t)?.trim();
    if (init?.startsWith("{")) t = init;
  }
  if (t.startsWith("{")) {
    const spreads = [...t.matchAll(/\.\.\.\s*([^,}]+)/g)];
    return spreads.some((s) => taint.isTainted((s[1] ?? "").trim(), at));
  }
  return taint.isTainted(t, at);
}

function sinksOf(f: FileCtx): Sink[] {
  return [...prismaSinks(f), ...builderSinks(f), ...mongoSinks(f), ...assignSinks(f)];
}

/** AUTH-010: the whole request body is written into an ORM call. */
export function massAssignment(f: FileCtx, project: Project): Raised[] {
  if (f.isClient) return [];
  const out: Raised[] = [];
  const seen = new Set<number>();
  const sinks = sinksOf(f);
  const taints = new Map<FunctionUnit, TaintAnalysis>();
  for (const sink of sinks) {
    const handler = f.handlers.find((h) => sink.index >= h.start && sink.index < h.end);
    if (!handler) continue;
    const taint = taints.get(handler) ?? analyzeTaint(f.src, handler);
    taints.set(handler, taint);
    if (seen.has(sink.index) || !wholeTainted(f, sink.value, sink.at, taint)) continue;
    seen.add(sink.index);
    const sensitive = sink.target !== undefined && project.sensitiveTargets.has(targetKey(sink.target));
    const validated = unitHas(f.src, handler, "validation");
    out.push({
      ...makeHit(f.src, "AUTH-010", sink.index),
      ...(sensitive ? { variant: "sensitive", note: `The target (${sink.target}) has role/admin/credit-style columns in this project.` } : {}),
      confidence: validated && !sensitive ? "medium" : "high",
    });
  }
  return out;
}

const STRIPE_CREATE = /\.\s*(?:checkout\s*\.\s*sessions|paymentIntents|prices|charges|invoiceItems|paymentLinks)\s*\.\s*create\s*\(/;
const AMOUNT_KEYS = ["unit_amount_decimal", "unit_amount", "amount", "price"];
const NUMERIC_WRAPPERS =
  /\b(?:Number|parseFloat|parseInt|BigInt|Decimal|Math\s*\.\s*(?:round|floor|ceil|abs|max|min|trunc)|toCents|\w*Cents)\s*\(/g;

function looksLikeStripeId(text: string): boolean {
  return /^["'`]price_/.test(text.trim()) || /(?:\bid|Id|ID|_id)\s*$/.test(text.trim());
}

/** AUTH-011 (tamper): amount/price for a Stripe object comes from the request. */
export function paymentTampering(f: FileCtx): Raised[] {
  if (f.isClient) return [];
  const out: Raised[] = [];
  for (const call of findCalls(f.src, STRIPE_CREATE)) {
    const unit = outermostUnit(f, call.index);
    if (!unit) continue;
    const taint = analyzeTaint(f.src, unit);
    for (const key of AMOUNT_KEYS) {
      const v = keyValue(f, call, key);
      if (!v) continue;
      if (key === "price" && looksLikeStripeId(v.text)) continue;
      if (taint.isTainted(v.text.replace(NUMERIC_WRAPPERS, "("), v.at)) {
        out.push({ ...makeHit(f.src, "AUTH-011", call.index), variant: "tamper" });
        break;
      }
    }
  }
  return out;
}

const SESSION_ID = /["']session_id["']|\bsession_id\b/;
const GRANT = /\b(?:is_?premium|is_?pro|is_?paid|plan|credits|subscription\w*|tier|has_?access|is_?subscribed)\s*:/i;
const WRITE = /\.\s*(?:update|upsert|insert|set|updateMany)\s*\(/;
const VERIFIES_PAYMENT = /\bsessions\s*\.\s*retrieve\s*\(|\bconstructEvent(?:Async)?\b|\bpaymentIntents\s*\.\s*retrieve\s*\(/;

/** AUTH-011 (success): a success page/route upgrades the account from session_id without asking Stripe. */
export function unverifiedSuccessPage(f: FileCtx): Raised[] {
  if (f.isClient) return [];
  const { src } = f;
  if (hasCode(src, VERIFIES_PAYMENT)) return [];
  const out: Raised[] = [];
  for (const u of f.units) {
    if (!u.exported && !f.handlers.includes(u)) continue;
    const m = codeMatches(src, SESSION_ID, u.start, u.end)[0];
    if (!m || !hasCode(src, GRANT, u.start, u.end) || !hasCode(src, WRITE, u.start, u.end)) continue;
    out.push({ ...makeHit(src, "AUTH-011", m.index), variant: "success" });
  }
  return out;
}
