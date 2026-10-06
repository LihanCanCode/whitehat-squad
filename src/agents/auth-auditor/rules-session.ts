import { exprEnd, matchClose } from "../../core/source/index.js";
import { findCalls, outermostUnit } from "./calls.js";
import { authNames, type FileCtx } from "./context.js";
import type { Raised } from "./report-types.js";
import { usedAsGate } from "./rules-client.js";
import { codeMatches, escapeRe, hasCode, makeHit } from "./util.js";

/** AUTH-008: Supabase getSession() trusted on the server without getUser()/getClaims() in the same unit. */
export function getSessionAuthz(f: FileCtx): Raised[] {
  if (!f.isServer) return [];
  const { src } = f;
  const out: Raised[] = [];
  for (const call of findCalls(src, /\.\s*auth\s*\.\s*getSession\s*\(/)) {
    const unit = outermostUnit(f, call.index);
    const start = unit?.start ?? 0;
    const end = unit?.end ?? src.code.length;
    if (hasCode(src, /\b(?:getUser|getClaims)\s*\(/, start, end)) continue;
    const usesUser = hasCode(src, /\bsession\??\.user\b|\bdata\??\.session\??\.user\b/, call.index, end);
    out.push({ ...makeHit(src, "AUTH-008", call.index), confidence: usesUser ? "high" : "medium" });
  }
  return out;
}

const META_KEYS = String.raw`(?:role|roles|is_admin|isAdmin|admin|plan|tier|isPro|is_pro|isPremium|is_premium|subscription)`;
const META_ACCESS = new RegExp(
  String.raw`\buser_metadata\s*\??\.\s*(${META_KEYS})\b|\buser_metadata\s*(?:\?\.)?\[\s*["'](${META_KEYS})["']\s*\]`,
);
// Bounded and brace-free: a line of thousands of `{` must stay linear (security review).
const META_DESTRUCTURE = new RegExp(String.raw`\{[^{}\n]{0,200}?\b(${META_KEYS})\b[^{}\n]{0,200}\}[ \t]*=[ \t]*[\w$.?]{0,80}user_metadata\b`);
const LINE_CONDITION = /===|!==|==|!=|\bif\s*\(|&&|(?<![?.])\?(?![.?])|\.includes\(/;

/** AUTH-009: user_metadata (user-editable) used for an authorization decision. app_metadata is safe. */
export function userMetadataAuthz(f: FileCtx): Raised[] {
  const { src } = f;
  const out: Raised[] = [];
  const seen = new Set<number>();
  const confidence = f.isClient ? "medium" : "high";
  for (const m of [...codeMatches(src, META_ACCESS), ...codeMatches(src, META_DESTRUCTURE)]) {
    const lineStart = src.code.lastIndexOf("\n", m.index - 1) + 1;
    if (seen.has(lineStart)) continue;
    const lineEnd = src.code.indexOf("\n", m.index);
    const line = src.code.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
    const decl = /\b(?:const|let|var)\s+(?:\{\s*)?(\w+)/.exec(line);
    const gated = LINE_CONDITION.test(line) || (!f.isClient && decl?.[1] !== undefined && usedAsGate(f, decl[1], lineEnd === -1 ? src.code.length : lineEnd));
    if (!gated) continue;
    seen.add(lineStart);
    out.push({ ...makeHit(src, "AUTH-009", m.index), confidence });
  }
  return out;
}

const AUTH_NAMES = ["user", "session", "currentUser", "authUser", "isAuthenticated", "isLoggedIn", "authenticated"];
const REJECTS = /\b(?:401|403)\b|Unauthori[sz]ed|Forbidden|Not authenticated/;

/** AUTH-016: `if (user) return 401/403` - the check is inverted. */
export function invertedAuthCheck(f: FileCtx): Raised[] {
  if (f.isClient) return [];
  const { src } = f;
  const out: Raised[] = [];
  for (const unit of f.units) {
    const names = [...new Set([...AUTH_NAMES, ...authNames(f, unit)])].map(escapeRe);
    const re = new RegExp(String.raw`\bif\s*\(\s*(?:${names.join("|")})\s*\)\s*`, "g");
    for (const m of codeMatches(src, re, unit.start, unit.end)) {
      const from = m.index + m[0].length;
      const end = src.bare.charAt(from) === "{" ? matchClose(src, from) : exprEnd(src, from, false);
      if (end < 0) continue;
      const body = src.code.slice(from, end);
      if (!REJECTS.test(body) || /already/i.test(body)) continue;
      if (/^\s*else\b/.test(src.bare.slice(end, end + 12))) continue;
      out.push(makeHit(src, "AUTH-016", m.index));
    }
  }
  return dedupeByLine(out);
}

function dedupeByLine(hits: Raised[]): Raised[] {
  const seen = new Set<string>();
  return hits.filter((h) => (seen.has(`${h.ruleId}:${h.line}`) ? false : (seen.add(`${h.ruleId}:${h.line}`), true)));
}

/** AUTH-018: allowDangerousEmailAccountLinking: true. */
export function dangerousLinking(f: FileCtx): Raised[] {
  return codeMatches(f.src, /\ballowDangerousEmailAccountLinking\s*:\s*true\b/).map((m) => makeHit(f.src, "AUTH-018", m.index));
}
