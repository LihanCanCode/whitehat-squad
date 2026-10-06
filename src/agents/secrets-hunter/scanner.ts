import { lineOf } from "../../core/finding.js";
import { redactSecret, scrubText } from "../../safety/redact.js";
import { PUBLIC_KEY_SHAPE, SECRET_PATTERNS } from "../../data/secret-patterns.js";
import type { Confidence, Severity } from "../../core/types.js";

export const GENERIC_RULE_ID = "SEC-090";
const MAX_MATCHES_PER_TEXT = 200;
const SNIPPET_CONTEXT = 60;
const MIN_GENERIC_LENGTH = 20;
const MIN_GENERIC_ENTROPY = 3.5;

export interface RawMatch {
  readonly ruleId: string;
  readonly name: string;
  readonly severity: Severity;
  readonly rotateUrl: string;
  readonly impact?: string;
  readonly value: string;
  readonly line: number;
  readonly confidence: Confidence;
  readonly isGeneric: boolean;
  /** Value sits in a NEXT_PUBLIC_/VITE_/REACT_APP_ style variable that is shipped to browsers. */
  readonly isPublicVar: boolean;
  /** Redacted single-line context. Never contains a raw secret. */
  readonly snippet: string;
}

export interface ScanTextOptions {
  /** Include the SEC-090 generic detector. */
  readonly generic: boolean;
  /** Only report secrets assigned to browser-exposed variables. */
  readonly publicOnly?: boolean;
}

const SKIP_PATH = /(?:^|\/)(?:node_modules|\.git)\/|\.map$|(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|go\.sum)$|\.lock$/;
const LOW_CONFIDENCE_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|docs?|examples?|samples?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|\.mdx?$/i;
const ENV_FILE = /(?:^|\/)\.env(?:\.[A-Za-z0-9_-]+)?$/;
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults?)$/;
const PUBLIC_VAR = /(?:^|[^A-Za-z0-9_])(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)\w*["']?\s*[:=]/;
// Owned by the supply-chain agent (SUP-008 reports registry tokens there), so skipped here to avoid a double report.
const SUPPLY_CHAIN_OWNED = /(?:^|\/)\.(?:npmrc|yarnrc\.yml|yarnrc)$/;
const LIVE_URL = /^https?:\/\//i;
const PLACEHOLDER =
  /example|your[_-]?(?:key|token|secret|api|password)|placeholder|change_?me|dummy|sample|redacted|<[^>]*>|\$\{|\{\{|%s|\*{3,}|x{4,}|(.)\1{7,}/i;
const GENERIC_ASSIGN =
  /\b([A-Za-z0-9_.-]{0,40}(?:key|secret|token|passw(?:or)?d|pwd)[A-Za-z0-9_.-]{0,20})["']?\s*[:=]\s*(["']?)([A-Za-z0-9+/=_.-]{20,100})\2/gi;

export const isSupplyChainOwnedPath = (p: string): boolean => SUPPLY_CHAIN_OWNED.test(p);
export const isLowConfidencePath = (p: string): boolean => !LIVE_URL.test(p) && LOW_CONFIDENCE_PATH.test(p);
export const isSkippedPath = (p: string): boolean => SKIP_PATH.test(p);
export const isEnvFile = (p: string): boolean => ENV_FILE.test(p);
export const isEnvTemplate = (p: string): boolean => isEnvFile(p) && ENV_TEMPLATE.test(p);

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export const isPlaceholder = (value: string): boolean => PLACEHOLDER.test(value);

interface Candidate {
  readonly pattern: { id: string; name: string; severity: Severity; rotateUrl: string; impact?: string } | null;
  readonly value: string;
  readonly valueIndex: number;
  readonly start: number;
  readonly end: number;
  readonly isGeneric: boolean;
}

function overlaps(ranges: readonly (readonly [number, number])[], start: number, end: number): boolean {
  return ranges.some(([s, e]) => start < e && end > s);
}

function collectPatternCandidates(text: string): Candidate[] {
  const out: Candidate[] = [];
  const covered: [number, number][] = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of text.matchAll(p.regex)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      if (overlaps(covered, start, end)) continue;
      const raw = m[1] ?? m[0];
      const value = raw.trim();
      if (!value || isPlaceholder(value)) continue;
      if (p.validate && !p.validate(value, m)) continue;
      const groupStart = m.indices?.[m[1] === undefined ? 0 : 1]?.[0] ?? start;
      const valueIndex = groupStart + (raw.length - raw.trimStart().length);
      covered.push([start, end]);
      out.push({ pattern: p, value, valueIndex, start, end, isGeneric: false });
      if (out.length >= MAX_MATCHES_PER_TEXT) return out;
    }
  }
  return out;
}

function collectGenericCandidates(text: string, allowUnquoted: boolean, taken: readonly Candidate[]): Candidate[] {
  const covered = taken.map((c) => [c.start, c.end] as const);
  const out: Candidate[] = [];
  for (const m of text.matchAll(GENERIC_ASSIGN)) {
    const quote = m[2] ?? "";
    const value = m[3] ?? "";
    if (!quote && !allowUnquoted) continue;
    const start = m.index ?? 0;
    const end = start + m[0].length;
    if (overlaps(covered, start, end)) continue;
    if (value.length < MIN_GENERIC_LENGTH || value.startsWith("eyJ") || PUBLIC_KEY_SHAPE.test(value)) continue;
    if (!/\d/.test(value) || !/[A-Za-z]/.test(value)) continue;
    if (isPlaceholder(value) || shannonEntropy(value) <= MIN_GENERIC_ENTROPY) continue;
    out.push({ pattern: null, value, valueIndex: start + m[0].lastIndexOf(value), start, end, isGeneric: true });
    if (out.length >= MAX_MATCHES_PER_TEXT) break;
  }
  return out;
}

function buildSnippet(text: string, c: Candidate, allValues: ReadonlySet<string>): string {
  const lineStart = text.lastIndexOf("\n", c.valueIndex - 1) + 1;
  const rawEnd = text.indexOf("\n", c.valueIndex);
  const lineEnd = rawEnd === -1 ? text.length : rawEnd;
  const valueEnd = c.valueIndex + c.value.length;
  const before = text.slice(Math.max(lineStart, c.valueIndex - SNIPPET_CONTEXT), c.valueIndex);
  const after = valueEnd <= lineEnd ? text.slice(valueEnd, Math.min(lineEnd, valueEnd + SNIPPET_CONTEXT)) : "";
  return `${scrubText(before, allValues)}${redactSecret(c.value)}${scrubText(after, allValues)}`.trim();
}

/** Finds secrets in a block of text. Pure: no I/O, never returns a snippet containing a raw secret. */
export function findSecrets(text: string, relPath: string, options: ScanTextOptions): RawMatch[] {
  const patternHits = collectPatternCandidates(text);
  const generic = options.generic
    ? collectGenericCandidates(text, isEnvFile(relPath), patternHits)
    : [];
  const all = [...patternHits, ...generic];
  const allValues = new Set(all.map((c) => c.value));
  // A live URL path like /docs/app.js is a site route, not a test or documentation file.
  const lowConfidencePath = isLowConfidencePath(relPath);
  const matches: RawMatch[] = [];
  for (const c of all) {
    const lineStart = text.lastIndexOf("\n", c.valueIndex - 1) + 1;
    const isPublicVar = PUBLIC_VAR.test(text.slice(lineStart, c.valueIndex));
    if (options.publicOnly && !isPublicVar) continue;
    const p = c.pattern;
    matches.push({
      ruleId: p ? p.id : GENERIC_RULE_ID,
      name: p ? p.name : "High-entropy secret-like value",
      severity: p ? p.severity : "medium",
      rotateUrl: p ? p.rotateUrl : "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
      ...(p?.impact ? { impact: p.impact } : {}),
      value: c.value,
      line: lineOf(text, c.valueIndex),
      confidence: c.isGeneric || lowConfidencePath ? "low" : "high",
      isGeneric: c.isGeneric,
      isPublicVar,
      snippet: buildSnippet(text, c, allValues),
    });
  }
  return matches;
}
