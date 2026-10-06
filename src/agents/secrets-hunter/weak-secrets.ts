import { lineOf } from "../../core/finding.js";
import { isEnvVarName, isReference, type Assignment } from "./config-values.js";

/** Why a literal application secret is unsafe. */
export type WeakReason = "known-default" | "short" | "fallback";

export interface WeakSecret extends Assignment {
  readonly reason: WeakReason;
  readonly fallback: boolean;
}

const MIN_STRONG_LENGTH = 32;
const MAX_LITERAL = 200;
const SECRET_NAME_SUFFIXES = ["jwtsecret", "authsecret", "sessionsecret", "cookiesecret", "appsecret", "secretkey", "encryptionkey"] as const;
// "STRIPE_SECRET_KEY" and friends belong to a provider; only app-level prefixes make SECRET_KEY an app secret.
const SECRET_KEY_PREFIXES: ReadonlySet<string> = new Set([
  "", "app", "django", "flask", "jwt", "session", "cookie", "auth", "nextauth", "signing", "encryption", "server", "node", "rails",
]);
const KNOWN_WEAK = new RegExp(
  "^(?:secret|changeme|change[-_ ]?me|replace[-_ ]?me|supersecret|super[-_ ]?secret|password|passw0rd|your[-_ ]?secret(?:[-_ ]?key)?(?:[-_ ]?here)?|" +
  "my[-_ ]?secret(?:[-_ ]?key)?|test|testing|dev|development|default|admin|qwerty|keyboard[-_ ]?cat|shh+|jwt[-_ ]?secret|secret[-_ ]?key|" +
  "todo|foo|bar|abc|abcdef|1234\\d*)$",
  "i",
);
const ANCHOR = /(?:jwt|auth|session|cookie|app)_?secret|secret_?key|encryption_?key/gi;
const IDENT_CHAR = /[A-Za-z0-9_$]/;
const QUOTED = String.raw`(["'\`])((?:\\.|(?!\1)[^\\\n]){0,${MAX_LITERAL}})\1`;
const ASSIGN_AFTER = new RegExp(String.raw`["']?\s*(?::|=(?![=>]))\s*${QUOTED}`, "y");
const FALLBACK_AFTER = new RegExp(String.raw`["']?\]?\s*(?:\|\||\?\?)\s*${QUOTED}`, "y");

/** True for the application-level secret names this rule covers (JWT_SECRET, AUTH_SECRET, SECRET_KEY, ...). */
export function isAppSecretName(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[_$]/g, "");
  if (normalized.endsWith("oauthsecret")) return false;
  const suffix = SECRET_NAME_SUFFIXES.find((s) => normalized.endsWith(s));
  if (!suffix) return false;
  return suffix !== "secretkey" || SECRET_KEY_PREFIXES.has(normalized.slice(0, -suffix.length));
}

/** Why a literal value is unsafe as an app secret, or null when it looks strong enough. */
export function weakReason(value: string): Exclude<WeakReason, "fallback"> | null {
  if (isReference(value)) return null;
  if (KNOWN_WEAK.test(value) || /^\d+$/.test(value) || /^(.)\1+$/.test(value)) return "known-default";
  if (value.length < MIN_STRONG_LENGTH) return isEnvVarName(value) ? null : "short";
  return null;
}

/** Weak literal for an env-style assignment (NAME=value in .env, compose, workflow, properties, Dockerfile). */
export function weakAssignment(a: Assignment): WeakSecret | null {
  if (!isAppSecretName(a.name)) return null;
  const reason = weakReason(a.value);
  return reason ? { ...a, reason, fallback: false } : null;
}

function identifierAt(text: string, start: number): { name: string; from: number; to: number } {
  let from = start;
  while (from > 0 && IDENT_CHAR.test(text[from - 1] ?? "")) from--;
  let to = start;
  while (to < text.length && IDENT_CHAR.test(text[to] ?? "")) to++;
  return { name: text.slice(from, to), from, to };
}

function literalAfter(re: RegExp, text: string, at: number): string | null {
  re.lastIndex = at;
  const value = re.exec(text)?.[2] ?? "";
  return value === "" || isReference(value) ? null : value;
}

/**
 * Weak or fallback application secrets in source/config text: `jwtSecret = "x"`,
 * `{ AUTH_SECRET: "x" }` and `process.env.JWT_SECRET || "x"`. Linear: it anchors on the name words
 * first and only then looks at what follows, so long minified lines stay cheap.
 */
export function findWeakInCode(text: string): WeakSecret[] {
  const out: WeakSecret[] = [];
  let resume = 0;
  for (const anchor of text.matchAll(ANCHOR)) {
    const index = anchor.index ?? 0;
    if (index < resume) continue;
    const ident = identifierAt(text, index);
    resume = ident.to;
    if (!isAppSecretName(ident.name)) continue;
    const fallback = literalAfter(FALLBACK_AFTER, text, ident.to);
    const assigned = fallback === null ? literalAfter(ASSIGN_AFTER, text, ident.to) : null;
    const value = fallback ?? assigned;
    if (value === null) continue;
    const reason = fallback === null ? weakReason(value) : (weakReason(value) ?? "fallback");
    if (!reason) continue;
    out.push({ name: ident.name, value, line: lineOf(text, ident.from), reason, fallback: fallback !== null });
  }
  return out;
}
