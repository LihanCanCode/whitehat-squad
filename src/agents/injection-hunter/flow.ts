import type { FunctionUnit, Span, TaintAnalysis } from "../../core/source/index.js";
import { matchClose, splitArgs } from "../../core/source/index.js";
import { expandedPieces, parsePieces, isChecked, isConstantPiece, isLookupPiece, relatedNames } from "./shared.js";
import type { FileCtx, Piece } from "./shared.js";

export interface ArgFlow {
  readonly pieces: readonly Piece[];
  /** Expression pieces that carry request data and are not constants, lookups or validated values. */
  readonly tainted: readonly Piece[];
  /** Request data reaches the argument but a validation (allowlist, anchored regex...) was found. */
  readonly checked: boolean;
}

export interface FlowOptions {
  /** Pieces to ignore (e.g. server base URLs for URL sinks). */
  readonly ignore?: (bare: string) => boolean;
  /** URL sink: `new URL(a, base)` pieces are replaced by the pieces of `a` (the part that can override the base). */
  readonly url?: boolean;
  /** Extra "this value is sanitized" test on the piece source plus its definitions. */
  readonly sanitized?: (ctx: FileCtx, unit: FunctionUnit, p: Piece, at: number) => boolean;
}

function unwrapNewUrl(ctx: FileCtx, p: Piece): Piece[] {
  const m = /^new\s+URL\s*\(/.exec(p.bare);
  if (p.kind !== "expr" || !m) return [p];
  const open = p.start + m[0].length - 1;
  const close = matchClose(ctx.src, open);
  const first = close < 0 ? undefined : splitArgs(ctx.src, open + 1, close - 1)[0];
  return first ? parsePieces(ctx.src, first) : [p];
}

/** Which parts of `arg` come from the request, after expanding local variables and applying shared guards. */
export function flowOf(ctx: FileCtx, unit: FunctionUnit, taint: TaintAnalysis, arg: Span, at: number, opts: FlowOptions = {}): ArgFlow {
  const expanded = expandedPieces(ctx, unit, arg, at);
  const pieces = opts.url ? expanded.flatMap((p) => unwrapNewUrl(ctx, p)) : expanded;
  const tainted = pieces.filter(
    (p) =>
      p.kind === "expr" &&
      taint.isTainted(p.bare, at) &&
      !isConstantPiece(p.bare) &&
      !isLookupPiece(p.bare, taint, at) &&
      !(opts.ignore?.(p.bare) ?? false) &&
      !(opts.sanitized?.(ctx, unit, p, at) ?? false),
  );
  if (tainted.length === 0) return { pieces, tainted, checked: false };
  const names = relatedNames(ctx, unit, tainted.map((p) => p.bare), at);
  if (isChecked(ctx, unit, names)) return { pieces, tainted: [], checked: true };
  return { pieces, tainted, checked: false };
}

/** Does the string being built contain literal text (so it is a composed string, not a bare value)? */
export const hasLiteralText = (pieces: readonly Piece[]): boolean => pieces.some((p) => p.kind === "lit" && p.text.trim() !== "");

/** Code of the unit, for guard regexes that are not tied to a single name. */
export const unitCode = (ctx: FileCtx, unit: FunctionUnit): string => ctx.src.code.slice(unit.start, unit.end);

/** Origin label for explanations, e.g. "req.body". */
export function describeOrigin(taint: TaintAnalysis, pieces: readonly Piece[], at: number): string {
  for (const p of pieces) {
    for (const m of p.bare.matchAll(/[A-Za-z_$][\w$]*/g)) {
      const o = taint.originOf(m[0], at);
      if (o) return o;
    }
    const direct = /(?<![\w$])(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies)|searchParams|formData|useSearchParams|location\.(?:search|hash)/.exec(p.bare);
    if (direct) return direct[0].replace(/\s+/g, "");
  }
  return "request input";
}

/** Has the literal text so far fixed the host of the URL (so later request data only reaches path or query)? */
function hostFixed(lit: string, mode: "ssrf" | "redirect"): boolean {
  if (mode === "ssrf") {
    const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(lit);
    return /[/?#]/.test(scheme ? lit.slice(scheme[0].length) : lit);
  }
  return /^[a-z][a-z0-9+.-]*:\/\/[^/?#\\@\0]*[/?#]/i.test(lit) || /^\/[^/\\]/.test(lit) || /^\0+[/?#]/.test(lit);
}

/**
 * Does request data reach the part of a URL string that decides where it points? Walks the pieces in order and
 * stops as soon as the literal text has pinned down the host. An untainted interpolation counts as the base.
 */
export function urlHostControlled(pieces: readonly Piece[], isTainted: (p: Piece) => boolean, mode: "ssrf" | "redirect"): boolean {
  let lit = "";
  for (const p of pieces) {
    if (p.kind === "lit") {
      lit += p.text;
      if (hostFixed(lit, mode)) return false;
    } else if (isTainted(p)) {
      return true;
    } else {
      lit += "\0";
    }
  }
  return false;
}
