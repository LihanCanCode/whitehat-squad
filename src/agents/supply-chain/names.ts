import { LEGIT_LOOKALIKES, POPULAR_LIST, POPULAR_PACKAGES } from "../../data/popular-packages.js";
import { damerauLevenshtein } from "./distance.js";

export type TyposquatKind = "edit-distance" | "homoglyph" | "scope-confusion";

export interface TyposquatHit {
  readonly kind: TyposquatKind;
  /** The popular package this name imitates. */
  readonly target: string;
  readonly distance: number;
}

const MIN_COMPARE_LENGTH = 4;
const SHORT_NAME_MAX = 6;

function scopeOf(name: string): string | null {
  return name.startsWith("@") && name.includes("/") ? name.slice(0, name.indexOf("/")) : null;
}

/** `@types-react` -> `@types/react` when that exists in the popular list. */
function scopeConfusionTarget(name: string): string | null {
  if (!name.startsWith("@") || name.includes("/")) return null;
  for (let i = 2; i < name.length - 1; i++) {
    if (name[i] !== "-") continue;
    const candidate = `${name.slice(0, i)}/${name.slice(i + 1)}`;
    if (POPULAR_PACKAGES.has(candidate)) return candidate;
  }
  return null;
}

const GLYPHS: Readonly<Record<string, string>> = { "0": "o", "3": "e", "4": "a", "5": "s", $: "s" };

/** Candidate de-obfuscations of a name (digits for letters, rn for m, vv for w). */
function glyphVariants(name: string): string[] {
  if (!/[0-9$]|rn|vv/.test(name)) return [];
  const base = [...name].map((c) => GLYPHS[c] ?? c).join("");
  const bases = base.includes("1") ? [base.replace(/1/g, "l"), base.replace(/1/g, "i")] : [base];
  const out = new Set<string>();
  for (const b of bases) {
    out.add(b);
    out.add(b.replace(/rn/g, "m"));
    out.add(b.replace(/vv/g, "w"));
  }
  out.delete(name);
  return [...out];
}

/**
 * Does `name` look like a deliberate imitation of a popular package?
 * Returns null for popular names, allowlisted lookalikes and anything not close enough.
 */
export function checkTyposquat(name: string): TyposquatHit | null {
  const lower = name.toLowerCase();
  if (POPULAR_PACKAGES.has(lower) || LEGIT_LOOKALIKES.has(lower)) return null;

  const scoped = scopeConfusionTarget(lower);
  if (scoped) return { kind: "scope-confusion", target: scoped, distance: 1 };

  for (const variant of glyphVariants(lower)) {
    if (POPULAR_PACKAGES.has(variant)) return { kind: "homoglyph", target: variant, distance: 1 };
  }

  if (lower.length < MIN_COMPARE_LENGTH) return null;
  // Distance 1 (incl. a transposition) only: distance 2 flags real, unrelated packages such as bcrypt-ts vs bcryptjs.
  const max = 1;
  const ownScope = scopeOf(lower);
  let best: TyposquatHit | null = null;
  for (const popular of POPULAR_LIST) {
    if (popular.length < MIN_COMPARE_LENGTH || Math.abs(popular.length - lower.length) > max) continue;
    // The real owner of a scope publishes siblings legitimately; squatters use a different scope.
    if (ownScope !== null && ownScope === scopeOf(popular)) continue;
    const distance = damerauLevenshtein(lower, popular, max);
    if (distance > 0 && distance <= max && (best === null || distance < best.distance)) {
      best = { kind: "edit-distance", target: popular, distance };
    }
  }
  return best;
}

const SLOP_SUFFIX = /^(.+?)-(?:utils?|helpers?|easy|sdk-js)$/;
const SLOP_REACT_HOOKS = /^react-[a-z0-9]+(?:-[a-z0-9]+)*-hooks$/;

/**
 * Names that look like what an LLM invents: `<popular>-utils`, `<popular>-helpers`,
 * `<popular>-sdk-js`, `<popular>-easy`, `react-<thing>-hooks`. Returns the imitated base, or null.
 */
export function slopBase(name: string): string | null {
  const lower = name.toLowerCase();
  if (POPULAR_PACKAGES.has(lower)) return null;
  const suffix = SLOP_SUFFIX.exec(lower);
  if (suffix?.[1] && POPULAR_PACKAGES.has(suffix[1])) return suffix[1];
  if (SLOP_REACT_HOOKS.test(lower)) return "react";
  return null;
}
