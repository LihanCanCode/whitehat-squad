import {
  createSource, isGeneratedPath, isTestPath, isVendorPath, lineOf, snippetAt, classifyPath,
  type FunctionUnit, type Source,
} from "../../core/source/index.js";

export const AGENT_ID = "auth-auditor";

export interface Hit {
  readonly ruleId: string;
  readonly file: string;
  readonly line: number;
  readonly snippet: string;
}

const SOURCE_EXT = /\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)$/;
const SKIP_FILE = /\.stories\.[jt]sx?$/;
const TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/i;
const TEST_DIR = /(?:^|\/)(?:__tests__|__mocks__|__fixtures__|fixtures?|specs?|e2e)\//i;
const TESTS_BEFORE_APP = /^(?:.*\/)?tests?\/(?:.*\/)?(?:app|pages)\//i;

/**
 * Test code is never scanned, with one exception: a Next.js route file that merely lives under an
 * `app/**\/test/` URL segment (app/api/test/route.ts) is production code that happens to be named "test".
 */
function isTestCode(path: string): boolean {
  const p = path.replace(/\\/g, "/");
  if (TEST_FILE.test(p) || TEST_DIR.test(p) || TESTS_BEFORE_APP.test(p)) return true;
  return isTestPath(p) && classifyPath(p) === undefined;
}

export function isScannable(path: string): boolean {
  return SOURCE_EXT.test(path) && !SKIP_FILE.test(path) && !isVendorPath(path) && !isGeneratedPath(path) && !isTestCode(path);
}

/** Hit located at a source offset (line and snippet come from the shared engine). */
export function makeHit(src: Source, ruleId: string, offset: number): Hit {
  return { ruleId, file: src.path, line: lineOf(src, offset), snippet: snippetAt(src, offset) };
}

/**
 * Regex matches in `src.code` whose first character is real code (not inside a string, template text,
 * regex or comment). `${...}` interpolations count as code.
 */
export function codeMatches(src: Source, re: RegExp, start = 0, end = src.code.length): RegExpExecArray[] {
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  rx.lastIndex = start;
  const out: RegExpExecArray[] = [];
  for (let m = rx.exec(src.code); m && m.index < end; m = rx.exec(src.code)) {
    if (m[0].length === 0) {
      rx.lastIndex++;
      continue;
    }
    const first = src.code.charAt(m.index);
    if (first.trim() !== "" && src.bare.charAt(m.index) === first) out.push(m);
  }
  return out;
}

export function hasCode(src: Source, re: RegExp, start = 0, end = src.code.length): boolean {
  return codeMatches(src, re, start, end).length > 0;
}

/** A pseudo unit spanning the whole file, for guard checks that are not tied to one function. */
export function fileUnit(src: Source): FunctionUnit {
  return { name: "<file>", kind: "function", exported: false, start: 0, end: src.code.length, bodyStart: 0, params: "" };
}

export function sourceOf(path: string, raw: string): Source {
  return createSource(path, raw);
}

/** Ranges that make up a unit (the declaration plus the registration call for named Express handlers). */
export function unitRanges(unit: FunctionUnit): Array<{ start: number; end: number }> {
  return [{ start: unit.start, end: unit.end }, ...(unit.extraRanges ?? [])];
}

export function codeMatchesInUnit(src: Source, re: RegExp, unit: FunctionUnit): RegExpExecArray[] {
  return unitRanges(unit).flatMap((r) => codeMatches(src, re, r.start, r.end));
}

export function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
