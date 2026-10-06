import { createSource, findUnits, handlerUnits, lineOf, snippetAt } from "../../core/source/index.js";
import type { FunctionUnit, Source } from "../../core/source/index.js";

const MARKUP = /\.(?:html?|vue|svelte)$/i;
const NL = String.fromCharCode(10);

export interface WebFile {
  readonly path: string;
  readonly text: string;
  /** Lexed JS: the file itself, or only its <script> blocks for markup files (same offsets as `text`). */
  readonly src: Source;
  readonly isMarkup: boolean;
  /** Markup with HTML comments blanked (same offsets); equals `text` for JS files. */
  readonly markup: string;
}

function blankKeepingNewlines(s: string): string {
  return s.replace(/[^\n]/g, " ");
}

/** Everything outside <script>...</script> blanked, so the lexer only sees JavaScript. */
function scriptsOnly(text: string): string {
  let out = "";
  let last = 0;
  for (const m of text.matchAll(/(<script\b[^>]*>)([\s\S]*?)(<\/script\s*>)/gi)) {
    const bodyStart = m.index + (m[1] ?? "").length;
    out += blankKeepingNewlines(text.slice(last, bodyStart)) + (m[2] ?? "");
    last = bodyStart + (m[2] ?? "").length;
  }
  return out + blankKeepingNewlines(text.slice(last));
}

export function loadWeb(path: string, text: string): WebFile {
  if (!MARKUP.test(path)) return { path, text, src: createSource(path, text), isMarkup: false, markup: text };
  const markup = text.replace(/<!--[\s\S]*?-->/g, (c) => blankKeepingNewlines(c));
  return { path, text, src: createSource(path, scriptsOnly(markup), { jsx: false }), isMarkup: true, markup };
}

export const lineAt = (f: WebFile, offset: number): number => lineOf(f.src, offset);
export function snippetOf(f: WebFile, offset: number): string {
  if (!f.isMarkup) return snippetAt(f.src, offset, 160);
  return (f.text.split(NL)[lineAt(f, offset) - 1] ?? "").trim().slice(0, 160);
}

/** Matches on `code` whose first character is real code (not comment, string text or regex body). */
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

/** Matches in the code view whose start is inside string text (header names, literal values). */
export function stringMatches(src: Source, re: RegExp): RegExpExecArray[] {
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const out: RegExpExecArray[] = [];
  for (const m of src.code.matchAll(rx)) {
    if (src.bare.charAt(m.index) !== src.code.charAt(m.index) || /["'`]/.test(src.code.charAt(m.index))) out.push(m);
  }
  return out;
}

/** Innermost handler, else outermost function, else a module-wide pseudo unit. */
export function scopeOf(f: WebFile, offset: number): FunctionUnit {
  let handler: FunctionUnit | undefined;
  for (const u of handlerUnits(f.src)) {
    if (offset >= u.start && offset < u.end && (!handler || u.end - u.start < handler.end - handler.start)) handler = u;
  }
  if (handler) return handler;
  let outer: FunctionUnit | undefined;
  for (const u of findUnits(f.src)) {
    if (offset >= u.start && offset < u.end && (!outer || u.end - u.start > outer.end - outer.start)) outer = u;
  }
  return outer ?? { name: "<module>", kind: "function", exported: false, start: 0, end: f.src.raw.length, bodyStart: 0, params: "" };
}

export { NL };
