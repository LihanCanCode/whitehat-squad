import type { BackendName, FrameworkName, SafeHttpClient } from "../../core/types.js";
import { extractBackendHints, mergeHints, type BackendHints } from "./hints.js";

export interface LiveSignals {
  readonly frameworks: ReadonlySet<FrameworkName>;
  readonly backends: ReadonlySet<BackendName>;
  readonly hints: BackendHints;
}

/** Landing page + up to 10 scripts. */
export const MAX_LIVE_REQUESTS = 11;
const MAX_SCRIPTS = MAX_LIVE_REQUESTS - 1;

function sameOriginScripts(html: string, base: URL): string[] {
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

async function tryGet(http: SafeHttpClient, url: string): Promise<string | null> {
  try {
    const res = await http.get(url);
    return res.status < 400 ? res.body : null;
  } catch {
    return null;
  }
}

function frameworkHints(text: string, fw: Set<FrameworkName>, be: Set<BackendName>): void {
  if (/\/_next\/static|__NEXT_DATA__/.test(text)) fw.add("next");
  if (/\/assets\/index-[\w-]+\.js/.test(text)) fw.add("vite");
  if (/__remixContext/.test(text)) fw.add("remix");
  if (/lovable/i.test(text)) {
    fw.add("vite");
    fw.add("react");
  }
  if (/js\.stripe\.com/.test(text)) be.add("stripe");
}

/** Fetches the landing page and same-origin scripts (<= 11 requests). Never throws. */
export async function scanLive(http: SafeHttpClient, target: URL): Promise<LiveSignals> {
  const frameworks = new Set<FrameworkName>();
  const backends = new Set<BackendName>();
  let hints: BackendHints = {};
  const html = await tryGet(http, target.href);
  if (html !== null) {
    const bodies = [html];
    for (const url of sameOriginScripts(html, target)) {
      const body = await tryGet(http, url);
      if (body !== null) bodies.push(body);
    }
    for (const body of bodies) {
      frameworkHints(body, frameworks, backends);
      hints = mergeHints(hints, extractBackendHints(body));
    }
  }
  if (hints.supabaseUrl) backends.add("supabase");
  if (hints.firebaseProjectId) backends.add("firebase");
  return { frameworks, backends, hints };
}
