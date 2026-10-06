import type { Finding } from "../../core/types.js";
import { exprEnd, matchClose, splitArgs } from "../../core/source/index.js";
import type { Span } from "../../core/source/index.js";
import { describeOrigin, flowOf, unitCode, urlHostControlled } from "./flow.js";
import { OWASP, bareOf, emit, findCalls, isBasePiece, replaceInLine } from "./shared.js";
import type { FileCtx } from "./shared.js";

const CALL_SINKS: readonly RegExp[] = [
  /(?<![\w$.])(?:redirect|permanentRedirect)\s*\(/,
  /(?<![\w$])(?:res|reply|response|ctx|c|context)\s*\.\s*redirect\s*\(/,
  /(?<![\w$])(?:NextResponse|Response)\s*\.\s*redirect\s*\(/,
  /(?<![\w$])(?:router|Router|history)\s*\.\s*(?:push|replace)\s*\(/,
  // Not `navigate(...)`: React Router / TanStack Router navigation is client-side routing inside the app
  // and cannot send the visitor to another origin (public-repo study: every navigate() hit was a false positive).
  /(?<![\w$.])(?:(?:window|document|self|top)\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(/,
];
const LOCATION_ASSIGN = /(?<![\w$.])(?:(?:window|document|self|top|globalThis)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?![=>])\s*/g;

const SLASH_ROOT = /startsWith\(\s*["'`]\/["'`]\s*\)|\/\^\\\/(?!\/)/;
const SLASH_NO_DOUBLE = /startsWith\(\s*["'`]\/\/["'`]\s*\)|\(\?!\\\/\)|includes\(\s*["'`]\/\/["'`]\s*\)|\\\\/;
const NAMED_GUARD =
  /\b(?:\w*[sS]afe\w*(?:Redirect|Url|Path|Next|Return|Target)\w*|\w*(?:Redirect|Url|Path|Next|Return|Target)\w*Safe\w*|isAllowed\w*|isRelative\w*|isInternal\w*|isLocal\w*|isSameOrigin\w*|isValidRedirect\w*|validateRedirect\w*|ALLOWED_\w+|allowed(?:Hosts?|Origins?|Redirects?|Paths?|Urls?)\w*|ALLOWLIST|allowlist|whitelist|WHITELIST)\b/;
const ORIGIN_COMPARE = /\.\s*(?:origin|host|hostname)\s*(?:===|!==|==|!=)|(?:includes|has|endsWith)\(\s*[\w$.]*\.(?:origin|hostname|host)\b/;

/** Route segments (`params.locale`, `locale`) cannot contain a slash, so after a leading "/" they cannot change the host. */
const ROUTE_SEGMENT = /^(?:(?:\w+\.)?params\.\w+|[\w$]*[lL]ocale[\w$]*|lang)$/;
/** The current page's own path (usePathname(), location.pathname) cannot change the origin. */
const OWN_PATH = /^(?:pathname|(?:window\s*\.\s*)?location\s*\.\s*pathname|usePathname\s*\(\s*\))$/;
const IGNORE = (bare: string): boolean => OWN_PATH.test(bare.trim()) || isBasePiece(bare) || ROUTE_SEGMENT.test(bare.replace(/\s+as\s+[\w.<>[\]| ]+/g, "").replace(/\s*(?:\|\||\?\?).*$/, "").replace(/[()]/g, "").trim());

function guarded(code: string): boolean {
  return NAMED_GUARD.test(code) || ORIGIN_COMPARE.test(code) || (SLASH_ROOT.test(code) && SLASH_NO_DOUBLE.test(code));
}

function unwrapNewUrl(ctx: FileCtx, s: Span): Span {
  const m = /^new\s+URL\s*\(/.exec(bareOf(ctx, s));
  if (!m) return s;
  const open = s.start + m[0].length - 1;
  const close = matchClose(ctx.src, open);
  return splitArgs(ctx.src, open + 1, close - 1)[0] ?? s;
}

interface Sink {
  readonly index: number;
  readonly open: number;
  readonly args: readonly Span[];
  readonly label: string;
}

function sinksOf(ctx: FileCtx): Sink[] {
  const out: Sink[] = [];
  for (const re of CALL_SINKS) {
    for (const call of findCalls(ctx, re)) {
      // `async redirect({ url }) { ... }` in a next-auth callbacks object is a definition, not a call.
      const after = /^\s*(\S)/.exec(ctx.src.bare.slice(call.close, call.close + 20))?.[1];
      if (after === "{") continue;
      out.push({ index: call.index, open: call.open, args: call.args, label: call.match[0].replace(/\s*\($/, "").trim() });
    }
  }
  const { code, bare } = ctx.src;
  for (const m of code.matchAll(LOCATION_ASSIGN)) {
    if (bare[m.index] !== code[m.index]) continue;
    if (/(?:const|let|var)\s+$/.test(code.slice(Math.max(0, m.index - 8), m.index))) continue;
    const start = m.index + m[0].length;
    const end = exprEnd(ctx.src, start);
    if (end > start) out.push({ index: m.index, open: m.index, args: [{ start, end }], label: m[0].replace(/\s*=\s*$/, "").trim() });
  }
  return out;
}

export function redirectFindings(ctx: FileCtx): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<number>();
  for (const sink of sinksOf(ctx)) {
    const unit = ctx.unitAt(sink.open);
    const taint = ctx.taintFor(unit, true);
    for (const raw of sink.args) {
      if (/^\d{3}$/.test(bareOf(ctx, raw).trim())) continue;
      const arg = unwrapNewUrl(ctx, raw);
      const flow = flowOf(ctx, unit, taint, arg, sink.open, { ignore: IGNORE, url: true });
      if (flow.tainted.length === 0 || seen.has(sink.index)) continue;
      const tainted = new Set(flow.tainted.map((p) => p.start));
      if (!urlHostControlled(flow.pieces, (p) => tainted.has(p.start), "redirect")) continue;
      if (guarded(unitCode(ctx, unit))) continue;
      seen.add(sink.index);
      const origin = describeOrigin(taint, flow.tainted, sink.open);
      // A server action can only be invoked by a POST the visitor makes themselves: a link cannot drive it.
      if (unit.role === "action" && !/searchParams|location/.test(origin)) continue;
      const templated = flow.pieces.length > 1;
      const after = replaceInLine(ctx, raw, `safeRedirectTarget(${ctx.src.code.slice(raw.start, raw.end)})`);
      findings.push(
        emit(ctx, {
          ruleId: "INJ-006",
          offset: sink.index,
          title: "Redirect target comes from the request (open redirect)",
          severity: "medium",
          explanation:
            `${sink.label} sends the visitor to an address taken from ${origin}. An attacker mails your users a link on your real domain with next=https://evil.example and, after they sign in, ` +
            "your own site bounces them to the attacker's look-alike page where a fake login or payment form steals their credentials. " +
            (templated
              ? "Joining it onto the site origin does not help: next=@evil.example makes the URL https://yoursite@evil.example, whose host is evil.example, and //evil.example is protocol-relative."
              : "Even a value that starts with / is not enough: //evil.example and /\\evil.example are treated as other hosts by browsers."),
          summary: "Accept only same-site relative paths (or an allowlist); fall back to a fixed page for anything else.",
          ...(after ? { after } : {}),
          config:
            "function safeRedirectTarget(next: string | null, fallback = \"/\"): string {\n  if (!next || !next.startsWith(\"/\") || next.startsWith(\"//\") || next.includes(\"\\\\\") || next.includes(\"@\")) return fallback;\n  return next;\n}\n" +
            "// or compare origins\nconst target = new URL(next, base);\nif (target.origin !== base.origin) return fallback;",
          prompt:
            `${sink.label} redirects to a value from ${origin}. Add a safeRedirectTarget() helper that only allows paths starting with a single "/" (reject "//", backslashes and "@") or hosts on an allowlist, and use it here; default to "/".`,
          references: [OWASP.redirect, "https://cwe.mitre.org/data/definitions/601.html"],
          cwe: "CWE-601",
        }),
      );
    }
  }
  return findings;
}
