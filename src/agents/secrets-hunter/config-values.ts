import { isPlaceholder, shannonEntropy } from "./scanner.js";

/** One `NAME = value` pair found in an env file, YAML block, Dockerfile, .properties file or code. */
export interface Assignment {
  readonly name: string;
  readonly value: string;
  readonly line: number;
}

const SECRET_NAME = /(?:secret|passw(?:or)?d|pwd|token|api[_.-]?key|private[_.-]?key|access[_.-]?key|auth[_.-]?key|credential)/i;
// Names that merely point at, describe or time-limit a secret rather than hold one.
const NON_SECRET_SUFFIX = /[._-](?:file|path|url|uri|id|name|ttl|expires?|expiry|header|endpoint|host|port|type|length|min|max|dir)$/i;
const PUBLIC_NAME = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)/;
const REFERENCE = /^\$|\$\{|\{\{|\$\(|^<[^>]*>$|^%[^%]*%$|^\*+$/;
const TRIVIAL = /^(?:true|false|\d+|on|off|yes|no|null|none|undefined)$/i;
const ENV_VAR_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const PLAIN_WORDS = /^[a-z]+(?:[-_.][a-z]+)*$/;
const PATH_OR_URL = /^(?:\.{0,2}\/|https?:\/\/[^@]*$)/i;
const MIN_LITERAL_SECRET_LENGTH = 12;
const MIN_LITERAL_SECRET_ENTROPY = 3;

export const isSecretishName = (name: string): boolean =>
  SECRET_NAME.test(name) && !NON_SECRET_SUFFIX.test(name) && !PUBLIC_NAME.test(name);

/** Empty values and references (`${VAR}`, `$VAR`, `${{ secrets.X }}`, `<token>`) are not literals. */
export const isReference = (value: string): boolean => value === "" || REFERENCE.test(value);

export const isEnvVarName = (value: string): boolean => ENV_VAR_NAME.test(value);

/**
 * A literal that is plausibly a real credential, for names that look like secrets: not a reference,
 * placeholder, flag, path or plain words, and long and random enough to be worth a look.
 */
export function isLiteralSecret(name: string, value: string): boolean {
  if (!isSecretishName(name) || isReference(value) || isPlaceholder(value) || /^your[_-]/i.test(value)) return false;
  if (TRIVIAL.test(value) || PATH_OR_URL.test(value) || PLAIN_WORDS.test(value) || /\s/.test(value)) return false;
  if (value.length < MIN_LITERAL_SECRET_LENGTH || shannonEntropy(value) < MIN_LITERAL_SECRET_ENTROPY) return false;
  return /\d/.test(value) || /[A-Z]/.test(value);
}

/**
 * Reads the value after `=` / `:`: a quoted string, or an unquoted token with any trailing
 * ` # comment` removed. Returns null for an unterminated quote.
 */
export function readValue(raw: string): string | null {
  const text = raw.trim();
  const quote = text[0];
  if (quote === '"' || quote === "'") {
    const end = text.indexOf(quote, 1);
    return end === -1 ? null : text.slice(1, end);
  }
  return text.replace(/\s+#.*$/, "").trim();
}
