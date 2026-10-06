import type { ScanContext } from "./types.js";

export interface LiveAsset {
  readonly url: string;
  readonly body: string;
}

export interface LiveAssets {
  readonly html: LiveAsset | null;
  readonly scripts: readonly LiveAsset[];
}

const MAX_SCRIPTS = 10;
const cache = new WeakMap<ScanContext, Promise<LiveAssets>>();

function sameOriginScriptUrls(html: string, base: URL): string[] {
  const urls: string[] = [];
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1] as string, base);
      if (u.origin === base.origin && !urls.includes(u.href)) urls.push(u.href);
    } catch {
      /* ignore malformed src */
    }
  }
  return urls.slice(0, MAX_SCRIPTS);
}

async function collect(ctx: ScanContext): Promise<LiveAssets> {
  if (!ctx.http || !ctx.target) return { html: null, scripts: [] };
  const page = await ctx.http.get(ctx.target.href);
  if (page.status >= 400) return { html: null, scripts: [] };
  const html: LiveAsset = { url: page.url, body: page.body };
  const scripts: LiveAsset[] = [];
  for (const url of sameOriginScriptUrls(page.body, ctx.target)) {
    const res = await ctx.http.get(url);
    if (res.status < 400) scripts.push({ url, body: res.body });
  }
  return { html, scripts };
}

/** The landing page and up to 10 same-origin scripts, fetched once per scan and shared by all agents. */
export function getLiveAssets(ctx: ScanContext): Promise<LiveAssets> {
  let hit = cache.get(ctx);
  if (!hit) {
    hit = collect(ctx);
    cache.set(ctx, hit);
  }
  return hit;
}
