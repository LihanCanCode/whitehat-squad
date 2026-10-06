import { callArgs, matchBracket } from "./pytext.js";
import type { FileCheck } from "./check.js";

const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|testing|e2e)\/|(?:^|\/)(?:test_[^/]*|[^/]*_tests?|conftest)\.py$/;
const EXAMPLE_PATH = /(?:^|\/)(?:examples?|samples?|demos?|docs?|tutorials?|scripts?\/examples?)\//;
const DEV_SETTINGS = /(?:^|\/)(?:[\w.-]*(?:dev|local|development|test|testing|debug|ci)[\w.-]*)\.py$/i;
const SETTINGS_PATH = /(?:^|\/)settings(?:[\w.-]*\.py|\/[\w.-]+\.py)$/;

export const isTestPath = (p: string): boolean => TEST_PATH.test(p);
export const isExamplePath = (p: string): boolean => EXAMPLE_PATH.test(p);
export const isDevSettings = (p: string): boolean => DEV_SETTINGS.test(p);

/** Django-style settings module: settings.py, settings_prod.py, settings/base.py, or has INSTALLED_APPS. */
export function isSettingsFile(fc: FileCheck): boolean {
  return SETTINGS_PATH.test(fc.path) || /^INSTALLED_APPS\s*=/m.test(fc.code);
}

export interface Call {
  /** Offset of the call expression's callee start (regex match start). */
  readonly index: number;
  /** Offset of the opening parenthesis. */
  readonly open: number;
  readonly end: number;
  readonly args: readonly { start: number; end: number }[];
}

/** Every call whose callee text matches `re` (the regex must end right before the `(`). */
export function callsMatching(fc: FileCheck, re: RegExp): Call[] {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const calls: Call[] = [];
  for (const m of fc.code.matchAll(new RegExp(re.source, flags))) {
    const open = m.index + m[0].length - 1;
    if (fc.code[open] !== "(") continue;
    const end = matchBracket(fc.code, open);
    if (end === -1) continue;
    calls.push({ index: m.index, open, end, args: callArgs(fc.code, open) });
  }
  return calls;
}

/**
 * Matches of `re` against the raw text, ignoring any that start inside a comment or string
 * (the code view differs from the raw text at the match start there).
 */
export type RawMatch = RegExpMatchArray & { index: number };

export function rawMatches(fc: FileCheck, re: RegExp): RawMatch[] {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const out: RawMatch[] = [];
  for (const m of fc.pt.raw.matchAll(new RegExp(re.source, flags))) {
    if (m.index !== undefined && fc.code[m.index] === fc.pt.raw[m.index]) out.push(m as RawMatch);
  }
  return out;
}

/** Name of the nearest class statement before `offset` ("" when at module level). */
export function enclosingClass(fc: FileCheck, offset: number): string {
  let name = "";
  for (const m of fc.code.slice(0, offset).matchAll(/^class[ \t]+(\w+)/gm)) name = m[1] as string;
  return name;
}

export function argText(fc: FileCheck, call: Call): string {
  return fc.code.slice(call.open + 1, call.end - 1);
}

export function rawArgText(fc: FileCheck, call: Call): string {
  return fc.pt.raw.slice(call.open + 1, call.end - 1);
}

/** Exact string-literal values inside a range of the file. */
export function stringValuesIn(fc: FileCheck, from: number, to: number): string[] {
  return fc.pt.strings.filter((s) => s.start >= from && s.end <= to).map((s) => s.value);
}

export function hasFramework(fc: FileCheck, ...names: string[]): boolean {
  return names.some((n) => (fc.frameworks as ReadonlySet<string>).has(n));
}

/** Offset of the unmatched `(` that encloses `pos`, or -1. */
export function enclosingCallOpen(code: string, pos: number): number {
  let depth = 0;
  for (let i = pos - 1; i >= 0; i--) {
    const c = code[i] as string;
    if (")]}".includes(c)) depth++;
    else if ("([{".includes(c)) {
      if (depth === 0) return c === "(" ? i : -1;
      depth--;
    }
  }
  return -1;
}

/** First non-space offset in a range. */
export function trimStart(code: string, from: number, to: number): number {
  let i = from;
  while (i < to && /\s/.test(code[i] as string)) i++;
  return i;
}
