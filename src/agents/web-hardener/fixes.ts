import { makeFinding } from "../../core/finding.js";
import type { Confidence, Evidence, Finding, Fix, Severity } from "../../core/types.js";

export const AGENT_ID = "web-hardener";

export const OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/";
const MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers";

export type HeaderKey = "csp" | "hsts" | "frame" | "nosniff" | "referrer" | "permissions";

export interface HeaderDef {
  readonly name: string;
  readonly value: string;
  readonly mdn: string;
}

export const HEADER_DEFS: Readonly<Record<HeaderKey, HeaderDef>> = {
  csp: {
    name: "Content-Security-Policy",
    value:
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; " +
      "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    mdn: `${MDN}/Content-Security-Policy`,
  },
  hsts: {
    name: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
    mdn: `${MDN}/Strict-Transport-Security`,
  },
  frame: { name: "X-Frame-Options", value: "DENY", mdn: `${MDN}/X-Frame-Options` },
  nosniff: { name: "X-Content-Type-Options", value: "nosniff", mdn: `${MDN}/X-Content-Type-Options` },
  referrer: { name: "Referrer-Policy", value: "strict-origin-when-cross-origin", mdn: `${MDN}/Referrer-Policy` },
  permissions: {
    name: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
    mdn: `${MDN}/Permissions-Policy`,
  },
};

export const ALL_HEADER_KEYS = Object.keys(HEADER_DEFS) as HeaderKey[];

/** Next.js `headers()` block for next.config. */
export function nextHeadersBlock(defs: readonly HeaderDef[]): string {
  const rows = defs.map((d) => `        { key: "${d.name}", value: ${JSON.stringify(d.value)} },`).join("\n");
  return `async headers() {\n  return [\n    {\n      source: "/(.*)",\n      headers: [\n${rows}\n      ],\n    },\n  ];\n},`;
}

/** Netlify / Cloudflare Pages `_headers` file. */
export function underscoreHeaders(defs: readonly HeaderDef[]): string {
  return `/*\n${defs.map((d) => `  ${d.name}: ${d.value}`).join("\n")}`;
}

/** vercel.json `headers` entry. */
export function vercelJson(defs: readonly HeaderDef[]): string {
  const headers = defs.map((d) => ({ key: d.name, value: d.value }));
  return JSON.stringify({ headers: [{ source: "/(.*)", headers }] }, null, 2);
}

/** Config text covering Next.js, Netlify `_headers` and Vercel. */
export function headersConfig(defs: readonly HeaderDef[]): string {
  return [
    "// Next.js: add inside next.config.js (module.exports = { ... })",
    nextHeadersBlock(defs),
    "",
    "# Netlify / Cloudflare Pages: public/_headers",
    underscoreHeaders(defs),
    "",
    "// Vercel (non-Next): vercel.json",
    vercelJson(defs),
  ].join("\n");
}

export interface MakeInput {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence?: Confidence;
  readonly explanation: string;
  readonly evidence: readonly Evidence[];
  readonly fix: Fix;
  readonly target: string;
  readonly cwe?: string;
}

export function make(input: MakeInput): Finding {
  return makeFinding({ agentId: AGENT_ID, ...input });
}

export function headerFinding(
  ruleId: string,
  key: HeaderKey,
  target: string,
  url: string,
  opts: { weakness?: string; severity: Severity; why: string; extraRefs?: readonly string[] },
): Finding {
  const def = HEADER_DEFS[key];
  const weak = opts.weakness !== undefined;
  const title = weak ? `${def.name} is present but weak` : `Missing ${def.name} header`;
  const problem = weak ? `The ${def.name} header is set but ${opts.weakness}.` : `The site does not send a ${def.name} header.`;
  return make({
    ruleId,
    title,
    severity: opts.severity,
    explanation: `${problem} ${opts.why}`,
    evidence: [{ url, snippet: weak ? `${def.name}: (weak) ${opts.weakness}` : `${def.name}: (not set)` }],
    fix: {
      summary: `Send \`${def.name}: ${def.value}\` on every response.`,
      config: headersConfig([def]),
      agentPrompt:
        `My deployed site ${target} is missing or has a weak ${def.name} header. ` +
        `Add \`${def.name}: ${def.value}\` to all responses using this project's hosting setup ` +
        `(Next.js headers() in next.config, Netlify _headers, or vercel.json). Keep the app working and tell me what you changed.`,
      references: [def.mdn, OWASP_HEADERS, ...(opts.extraRefs ?? [])],
    },
    target,
    cwe: "CWE-693",
  });
}
