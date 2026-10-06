import { stripControl } from "./util.js";

/** Neutralise HTML and markdown syntax in untrusted prose. */
export function esc(input: string): string {
  return stripControl(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_[\]|#])/g, "\\$1");
}

/** Single-line escaped text. */
export const escLine = (s: string): string => esc(s).replace(/\s*\n\s*/g, " ");

/** Identifier safe inside an inline code span. */
export const code = (s: string): string => `\`${stripControl(s).replace(/[`\n]/g, "")}\``;

/** Fenced block whose fence is longer than any backtick run in the body. */
export function fence(body: string, lang = ""): string {
  const clean = stripControl(body);
  const longest = Math.max(0, ...(clean.match(/`+/g) ?? []).map((m) => m.length));
  const bar = "`".repeat(Math.max(3, longest + 1));
  return `${bar}${lang}\n${clean}\n${bar}`;
}

