import type { Finding } from "../../core/types.js";
import { matchClose, splitArgs } from "../../core/source/index.js";
import type { Span } from "../../core/source/index.js";
import { describeOrigin, flowOf, unitCode, urlHostControlled } from "./flow.js";
import { OWASP, bareOf, codeOf, emit, findCalls, isBasePiece, replaceInLine } from "./shared.js";
import type { Call, FileCtx } from "./shared.js";

const HTTP_IMPORT = /["'](?:got|ky|ky-universal|undici|axios|node-fetch|needle)["']/;
const FETCH = /(?<![\w$.])(?:(?:globalThis|window|self)\s*\.\s*)?fetch\s*\(/;
const AXIOS = /(?<![\w$.])axios\s*(?:\.\s*(?:get|post|put|patch|delete|head|request|options)\s*)?\(/;
const GOT_KY = /(?<![\w$.])(?:got|ky)\s*(?:\.\s*(?:get|post|put|patch|delete|head)\s*)?\(/;
const UNDICI = /(?<![\w$.])undici\s*\.\s*(?:request|fetch|stream)\s*\(/;
const NODE_HTTP = /(?<![\w$.])https?\s*\.\s*(?:get|request)\s*\(/;

const IGNORE = isBasePiece;

/** The user already restricts where the server may connect. */
const SSRF_GUARD =
  /\b(?:ALLOWED_\w+|allowed(?:Hosts?|Origins?|Domains?|Urls?)\w*|ALLOWLIST|allowlist|whitelist|WHITELIST|isSafe\w*Url\w*|isAllowed\w*|validateUrl\w*|assertSafe\w*|safeFetch|isPrivate\w*|ssrf)\b|\.\s*(?:hostname|host|origin)\s*(?:===|!==|==|!=)|(?:includes|has|endsWith)\(\s*[\w$.]*\.(?:hostname|host|origin)\b/i;

/** First argument of `new URL(a, b)` (the part that can override the base), else the span itself. */
function unwrapNewUrl(ctx: FileCtx, s: Span): Span {
  const m = /^new\s+URL\s*\(/.exec(bareOf(ctx, s));
  if (!m) return s;
  const open = s.start + m[0].length - 1;
  const close = matchClose(ctx.src, open);
  return splitArgs(ctx.src, open + 1, close - 1)[0] ?? s;
}

/** The URL argument: arg0, or the `url:` property of an options object (axios / got style). */
function urlArg(ctx: FileCtx, call: Call): Span | undefined {
  const first = call.args[0];
  if (!first) return undefined;
  if (!bareOf(ctx, first).startsWith("{")) return unwrapNewUrl(ctx, first);
  for (const prop of splitArgs(ctx.src, first.start + 1, first.end - 1)) {
    const m = /^url\s*:\s*/.exec(bareOf(ctx, prop));
    if (m) return unwrapNewUrl(ctx, { start: prop.start + m[0].length, end: prop.end });
  }
  return undefined;
}

export function ssrfFindings(ctx: FileCtx): Finding[] {
  if (ctx.isClient) return [];
  const sinks: Call[] = [...findCalls(ctx, FETCH), ...findCalls(ctx, AXIOS), ...findCalls(ctx, UNDICI), ...findCalls(ctx, NODE_HTTP)];
  if (HTTP_IMPORT.test(ctx.src.raw)) sinks.push(...findCalls(ctx, GOT_KY));
  const findings: Finding[] = [];
  for (const call of sinks) {
    const arg = urlArg(ctx, call);
    if (!arg) continue;
    const unit = ctx.unitAt(call.open);
    const taint = ctx.taintFor(unit);
    const flow = flowOf(ctx, unit, taint, arg, call.open, { ignore: IGNORE, url: true });
    if (flow.tainted.length === 0) continue;
    const tainted = new Set(flow.tainted.map((p) => p.start));
    if (!urlHostControlled(flow.pieces, (p) => tainted.has(p.start), "ssrf")) continue;
    if (SSRF_GUARD.test(unitCode(ctx, unit))) continue;
    const origin = describeOrigin(taint, flow.tainted, call.open);
    const fn = call.match[0].replace(/\s*\($/, "").trim();
    const whole = flow.pieces.length === 1;
    const after = replaceInLine(ctx, arg, `assertAllowedUrl(${codeOf(ctx, arg)})`);
    findings.push(
      emit(ctx, {
        ruleId: "INJ-005",
        offset: call.index,
        title: "Server fetches a URL chosen by the request (SSRF)",
        severity: "high",
        explanation:
          `${fn}() requests ${whole ? "a URL taken directly from" : "a URL whose host or scheme comes from"} ${origin}. Anyone who can call this endpoint can make your server ` +
          "send requests to addresses only the server can reach: cloud metadata services (http://169.254.169.254, which hands out cloud credentials), localhost admin ports, " +
          "and internal databases or dashboards. The response is often returned or logged, so the attacker can read it.",
        summary: "Only fetch URLs whose host is on an allowlist (https only); never accept a full URL or host from the request.",
        ...(after ? { after } : {}),
        config:
          "const ALLOWED_HOSTS = new Set([\"api.example.com\"]);\nfunction assertAllowedUrl(input: string): URL {\n  const u = new URL(input);\n  if (u.protocol !== \"https:\" || !ALLOWED_HOSTS.has(u.hostname)) throw new Error(\"URL not allowed\");\n  return u;\n}\n" +
          "// or keep the origin fixed and let the request choose only an id\nawait fetch(`https://api.example.com/items/${encodeURIComponent(id)}`);",
        prompt:
          `${fn}() fetches a URL derived from ${origin}. Add an allowlist check (parse with new URL, require https, hostname in an ALLOWED_HOSTS set, no redirects to other hosts) before the request, or build the URL from a fixed origin plus an encoded id.`,
        references: [OWASP.ssrf, "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
        cwe: "CWE-918",
      }),
    );
  }
  return findings;
}
