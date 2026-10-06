import { lineOf } from "../../core/finding.js";
import { createSource } from "../../core/source/index.js";
import { redactSecret } from "../../safety/redact.js";
import { isLiteralSecret, readValue, type Assignment } from "./config-values.js";
import { isEnvFile, isEnvTemplate, isLowConfidencePath } from "./scanner.js";
import { structuredAssignments, structuredKind } from "./structured-config.js";
import { findWeakInCode, weakAssignment, type WeakReason } from "./weak-secrets.js";
import type { Confidence } from "../../core/types.js";

export const WEAK_SECRET_RULE_ID = "SEC-110";
export const LITERAL_SECRET_RULE_ID = "SEC-111";

export interface ConfigSecretMatch {
  readonly ruleId: typeof WEAK_SECRET_RULE_ID | typeof LITERAL_SECRET_RULE_ID;
  readonly name: string;
  readonly value: string;
  readonly line: number;
  readonly confidence: Confidence;
  readonly reason: WeakReason | "literal";
  readonly fallback: boolean;
  /** `NAME = ****` style single line; never contains the raw value. */
  readonly snippet: string;
}

export interface ConfigScanOptions {
  /** The env file is gitignored: a weak local value matters much less than a tracked one. */
  readonly ignoredEnv: boolean;
}

const ENV_ASSIGNMENT = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$/gm;
const PYTHON_FILE = /\.py$/i;
const JS_FILE = /\.[cm]?[jt]sx?$/i;

/** JS/TS with comments blanked (offsets kept): a doc comment showing `JWT_SECRET || "x"` is not code. */
function codeView(text: string, file: string): string {
  return JS_FILE.test(file) ? createSource(file, text).code : text;
}

function envAssignments(text: string): Assignment[] {
  const out: Assignment[] = [];
  for (const m of text.matchAll(ENV_ASSIGNMENT)) {
    const value = readValue(m[2] ?? "");
    if (value === null) continue;
    const before = text.slice(0, m.index ?? 0);
    out.push({ name: m[1] ?? "", value, line: before.split("\n").length });
  }
  return out;
}

function confidenceFor(file: string, base: Confidence, options: ConfigScanOptions): Confidence {
  return isLowConfidencePath(file) || options.ignoredEnv ? "low" : base;
}

function toMatch(
  a: Assignment, ruleId: ConfigSecretMatch["ruleId"], reason: ConfigSecretMatch["reason"], confidence: Confidence, fallback: boolean,
): ConfigSecretMatch {
  const shown = fallback ? `process.env.${a.name} || ${redactSecret(a.value)}` : `${a.name} = ${redactSecret(a.value)}`;
  return { ruleId, name: a.name, value: a.value, line: a.line, confidence, reason, fallback, snippet: shown };
}

function fromAssignments(assignments: readonly Assignment[], file: string, options: ConfigScanOptions, literals: boolean): ConfigSecretMatch[] {
  const out: ConfigSecretMatch[] = [];
  for (const a of assignments) {
    const weak = weakAssignment(a);
    if (weak) {
      const base: Confidence = weak.reason === "known-default" ? "high" : "medium";
      out.push(toMatch(a, WEAK_SECRET_RULE_ID, weak.reason, confidenceFor(file, base, options), false));
    } else if (literals && isLiteralSecret(a.name, a.value)) {
      out.push(toMatch(a, LITERAL_SECRET_RULE_ID, "literal", confidenceFor(file, "medium", options), false));
    }
  }
  return out;
}

/**
 * Weak application secrets (SEC-110) everywhere they can be assigned, plus literal secrets in
 * compose / workflow / Dockerfile / .properties files (SEC-111). Env templates are never reported.
 */
export function findConfigSecrets(text: string, file: string, options: ConfigScanOptions): ConfigSecretMatch[] {
  if (isEnvFile(file)) return isEnvTemplate(file) ? [] : fromAssignments(envAssignments(text), file, options, false);
  const kind = structuredKind(file);
  if (kind) return fromAssignments(structuredAssignments(text, kind), file, options, true);
  if (PYTHON_FILE.test(file)) return [];
  return findWeakInCode(codeView(text, file)).map((w) => {
    const base: Confidence = w.fallback || w.reason === "known-default" ? "high" : "medium";
    return toMatch(w, WEAK_SECRET_RULE_ID, w.reason, confidenceFor(file, base, options), w.fallback);
  });
}
