import { classifyPath } from "../../core/source/index.js";
import type { Finding, ScanContext } from "../../core/types.js";
import { HEADER_DEFS, OWASP_HEADERS, make, nextHeadersBlock } from "./fixes.js";
import { bareMatches, codeMatches, lineAt, snippetOf } from "./util.js";
import type { WebFile } from "./util.js";

export const NEXT_CONFIG = /(?:^|\/)next\.config\.(?:js|mjs|cjs|ts|mts)$/;
const VITE_CONFIG = /(?:^|\/)vite\.config\.(?:js|mjs|cjs|ts)$/;
const WEBPACK_CONFIG = /(?:^|\/)webpack(?:\.[\w-]+)?\.config\.(?:js|mjs|cjs|ts)$/;
const SECURITY_HEADER = /Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options/i;
const HEADER_LIBS = /["'](?:next-secure-headers|@next-safe\/middleware|nosecone|@nosecone\/next|helmet|next-safe)["']/;

// ---------------------------------------------------------------------------------------------
// WEB-001 source maps

export function sourceMapFindings(file: WebFile, target: string): Finding[] {
  let m: RegExpExecArray | undefined;
  let label = "";
  if (NEXT_CONFIG.test(file.path)) {
    m = bareMatches(file.src, /productionBrowserSourceMaps\s*:\s*true\b/)[0];
    label = "productionBrowserSourceMaps: true";
  } else if (VITE_CONFIG.test(file.path)) {
    m = codeMatches(file.src, /\bsourcemap\s*:\s*(?:true\b|["']inline["'])/)[0];
    label = "build.sourcemap exposes source maps";
  } else if (WEBPACK_CONFIG.test(file.path)) {
    m = codeMatches(file.src, /\bdevtool\s*:\s*["'](?:inline-)?source-map["']/)[0];
    label = "devtool: 'source-map'";
  }
  if (!m) return [];
  const line = lineAt(file, m.index);
  return [
    make({
      ruleId: "WEB-001",
      title: "Production source maps are enabled",
      severity: "low",
      explanation:
        `Your build config enables public source maps (${label}). Anyone can open browser dev tools and read your ` +
        "original, unminified source code, which makes finding other bugs and leaked logic much easier.",
      evidence: [{ file: file.path, line, snippet: snippetOf(file, m.index) }],
      fix: {
        summary: "Disable public source maps in production, or upload them privately to your error tracker (e.g. 'hidden').",
        config: "// next.config.js\nproductionBrowserSourceMaps: false\n// vite.config.ts\nbuild: { sourcemap: 'hidden' }\n// webpack\ndevtool: false",
        agentPrompt: `In ${file.path} at line ${line}, turn off public production source maps (Next: productionBrowserSourceMaps false; Vite: build.sourcemap 'hidden' or false; webpack: no devtool in production). Do not change dev behavior.`,
        references: ["https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps", OWASP_HEADERS],
      },
      target,
      cwe: "CWE-540",
    }),
  ];
}

// ---------------------------------------------------------------------------------------------
// WEB-004 security headers (next.config, middleware / proxy, vercel.json, netlify.toml, _headers)

const dirOf = (p: string): string => p.slice(0, Math.max(0, p.lastIndexOf("/")));
const related = (appDir: string, otherDir: string): boolean =>
  otherDir === "" || appDir === "" || appDir === otherDir || appDir.startsWith(`${otherDir}/`) || otherDir.startsWith(`${appDir}/`);

function configHasHeaders(config: WebFile): boolean {
  return bareMatches(config.src, /\bheaders\s*(?:\(|:|=)/).length > 0 || HEADER_LIBS.test(config.src.code);
}

async function externalSetsHeaders(ctx: ScanContext, files: readonly WebFile[], appDir: string): Promise<boolean> {
  if (files.some((f) => classifyPath(f.path) === "middleware" && related(appDir, dirOf(f.path)) && (SECURITY_HEADER.test(f.src.code) || HEADER_LIBS.test(f.src.code)))) return true;
  for (const p of ctx.files.paths) {
    const base = p.slice(p.lastIndexOf("/") + 1);
    if (!(base === "vercel.json" || base === "netlify.toml" || base === "_headers") || !related(appDir, dirOf(p))) continue;
    const text = await ctx.files.read(p);
    if (!text || !SECURITY_HEADER.test(text)) continue;
    if (base === "vercel.json" && !/"headers"/.test(text)) continue;
    if (base === "netlify.toml" && !/\[\[headers\]\]/.test(text)) continue;
    return true;
  }
  return false;
}

async function nextApps(ctx: ScanContext, files: readonly WebFile[]): Promise<Array<{ file: string; line: number; snippet: string; config?: WebFile }>> {
  const configs = files.filter((f) => NEXT_CONFIG.test(f.path));
  if (configs.length > 0) {
    return configs.map((config) => {
      const m = bareMatches(config.src, /\bmodule\s*\.\s*exports\b|\bexport\s+default\b|\bconst\s+nextConfig\b/)[0];
      const at = m?.index ?? 0;
      return { file: config.path, line: lineAt(config, at), snippet: snippetOf(config, at) || "no headers() / security-header config found", config };
    });
  }
  if (!ctx.stack.frameworks.includes("next")) return [];
  // No next.config anywhere: point at every package.json that depends on next (one per app in a monorepo).
  const apps: Array<{ file: string; line: number; snippet: string }> = [];
  const manifests = ctx.files.paths.filter((p) => /(?:^|\/)package\.json$/.test(p) && !p.includes("node_modules/")).sort();
  for (const pkgPath of manifests) {
    const pkg = await ctx.files.read(pkgPath);
    const idx = pkg ? pkg.search(/["']next["']\s*:/) : -1;
    if (pkg && idx >= 0) apps.push({ file: pkgPath, line: pkg.slice(0, idx).split("\n").length, snippet: '"next" dependency; no security headers configured' });
  }
  return apps.length > 0 ? apps : [{ file: "", line: 0, snippet: "no headers() / security-header config found" }];
}

export async function nextHeaderFindings(files: readonly WebFile[], ctx: ScanContext, target: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const defs = Object.values(HEADER_DEFS);
  for (const app of await nextApps(ctx, files)) {
    if (app.config && configHasHeaders(app.config)) continue;
    if (await externalSetsHeaders(ctx, files, dirOf(app.file))) continue;
    const where = app.file || "next.config.js";
    out.push(
      make({
        ruleId: "WEB-004",
        title: "Next.js app does not configure security headers",
        severity: "low",
        explanation:
          "No headers() in next.config, no middleware/proxy, vercel.json, netlify.toml or _headers file sets CSP, HSTS or frame protection, so browsers get no instructions to block clickjacking, " +
          "MIME sniffing or injected scripts. These headers are cheap defense-in-depth.",
        evidence: [{ ...(app.file ? { file: app.file, line: app.line } : {}), snippet: app.snippet }],
        fix: {
          summary: "Add a headers() block to next.config with the standard security headers.",
          config: nextHeadersBlock(defs),
          agentPrompt: `Add this headers() function to ${where}${app.line ? ` (near line ${app.line})` : ""} inside the exported config so all routes send security headers, then run the app and confirm nothing breaks (adjust CSP if inline scripts are needed):\n${nextHeadersBlock(defs)}`,
          references: ["https://nextjs.org/docs/app/api-reference/config/next-config-js/headers", OWASP_HEADERS],
        },
        target,
        cwe: "CWE-693",
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// WEB-007 open image optimizer, WEB-008 SVG via the optimizer

function imagesBlock(file: WebFile): { start: number; text: string } | undefined {
  const m = bareMatches(file.src, /\bimages\s*:\s*\{/)[0];
  if (!m) return undefined;
  const open = m.index + m[0].length - 1;
  let depth = 0;
  for (let i = open; i < file.src.bare.length; i++) {
    const ch = file.src.bare.charAt(i);
    if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return { start: open, text: file.src.code.slice(open, i + 1) };
  }
  return undefined;
}

export function imageConfigFindings(file: WebFile, target: string): Finding[] {
  if (!NEXT_CONFIG.test(file.path)) return [];
  const block = imagesBlock(file);
  if (!block) return [];
  const out: Finding[] = [];
  const wildcard = /\bhostname\s*:\s*["'`]\*{1,2}["'`]|\bdomains\s*:\s*\[[^\]]*["'`]\*["'`]/.exec(block.text);
  if (wildcard) {
    const at = block.start + wildcard.index;
    const line = lineAt(file, at);
    out.push(
      make({
        ruleId: "WEB-007",
        title: "Next.js image optimizer accepts images from any host",
        severity: "medium",
        confidence: "high",
        explanation:
          "images.remotePatterns (or domains) allows every hostname, so /_next/image will fetch and re-serve any URL an attacker supplies. " +
          "That turns your server into a free image proxy and CDN (bandwidth and CPU bill), a way to launder abusive content under your domain, and a path to probe internal addresses.",
        evidence: [{ file: file.path, line, snippet: snippetOf(file, at) }],
        fix: {
          summary: "List the exact hosts you load images from.",
          config: "images: {\n  remotePatterns: [{ protocol: 'https', hostname: 'images.example.com', pathname: '/uploads/**' }],\n}",
          agentPrompt: `In ${file.path} at line ${line}, replace the wildcard images.remotePatterns hostname (or domains: ['*']) with the exact hostnames and path prefixes this app really loads images from. Do not use '**' or '*' as a hostname.`,
          references: ["https://nextjs.org/docs/app/api-reference/components/image#remotepatterns", "https://cwe.mitre.org/data/definitions/918.html"],
        },
        target,
        cwe: "CWE-918",
      }),
    );
  }
  const svg = /\bdangerouslyAllowSVG\s*:\s*true\b/.exec(block.text);
  if (svg) {
    const csp = /contentSecurityPolicy\s*:\s*("[^"]*"|'[^']*'|`[^`]*`)/.exec(block.text);
    const disposition = /contentDispositionType\s*:\s*["'](\w+)["']/.exec(block.text);
    const cspOk = csp !== null && /\bsandbox\b/.test(csp[1] ?? "");
    const dispOk = disposition?.[1] === "attachment";
    if (!(cspOk && dispOk)) {
      const at = block.start + svg.index;
      const line = lineAt(file, at);
      const explicit = (csp !== null && !cspOk) || (disposition !== null && !dispOk);
      out.push(
        make({
          ruleId: "WEB-008",
          title: "Next.js image optimizer serves SVG without a sandbox",
          severity: "medium",
          confidence: explicit ? "high" : "low",
          explanation:
            "dangerouslyAllowSVG lets /_next/image serve SVG files, which can contain script. Without a sandboxing contentSecurityPolicy and contentDispositionType 'attachment', opening the image URL directly can run attacker script on your origin. " +
            (explicit ? "Your config sets one of those options to a weaker value." : "Recent Next versions default to safe values, so confidence is low unless you override them."),
          evidence: [{ file: file.path, line, snippet: snippetOf(file, at) }],
          fix: {
            summary: "Keep SVG sandboxed: CSP with sandbox and attachment disposition, or avoid dangerouslyAllowSVG.",
            config: "images: {\n  dangerouslyAllowSVG: true,\n  contentDispositionType: 'attachment',\n  contentSecurityPolicy: \"default-src 'self'; script-src 'none'; sandbox;\",\n}",
            agentPrompt: `In ${file.path} at line ${line}, either remove images.dangerouslyAllowSVG or add contentDispositionType: 'attachment' and contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;" next to it.`,
            references: ["https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowsvg", "https://cwe.mitre.org/data/definitions/79.html"],
          },
          target,
          cwe: "CWE-79",
        }),
      );
    }
  }
  return out;
}
