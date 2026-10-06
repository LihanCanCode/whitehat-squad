const MIN_REDACT_LENGTH = 8;
const VISIBLE = 4;

/** Keeps the first and last 4 characters. Short values are fully masked. */
export function redactSecret(value: string): string {
  if (value.length < MIN_REDACT_LENGTH + VISIBLE) return "*".repeat(Math.max(value.length, 4));
  return `${value.slice(0, VISIBLE)}${"*".repeat(8)}${value.slice(-VISIBLE)}`;
}

/** Replaces every known raw secret inside `text` with its redacted form. */
export function scrubText(text: string, secrets: ReadonlySet<string>): string {
  let out = text;
  // Longest first so a secret containing another is replaced whole.
  const ordered = [...secrets].filter((s) => s.length >= MIN_REDACT_LENGTH).sort((a, b) => b.length - a.length);
  for (const secret of ordered) {
    out = out.split(secret).join(redactSecret(secret));
  }
  return out;
}
