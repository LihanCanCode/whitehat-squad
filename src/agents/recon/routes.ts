export const MAX_ROUTES = 200;

const APP_RE = /(?:^|\/)(?:src\/)?app\/(?:(.*)\/)?(?:page|route)\.(?:tsx|ts|jsx|js|mjs)$/;
const PAGES_RE = /(?:^|\/)(?:src\/)?pages\/(.+)\.(?:tsx|ts|jsx|js|mjs)$/;

function cleanSegments(raw: string): string[] {
  return raw
    .split("/")
    .filter((s) => s !== "" && !(s.startsWith("(") && s.endsWith(")")) && !s.startsWith("@"));
}

const toUrl = (segments: string[]): string => "/" + segments.join("/");

function routeFor(path: string): string | null {
  const app = APP_RE.exec(path);
  if (app) return toUrl(cleanSegments(app[1] ?? ""));
  const pages = PAGES_RE.exec(path);
  if (pages) {
    const segs = cleanSegments(pages[1] as string);
    const last = segs[segs.length - 1];
    if (last?.startsWith("_")) return null;
    if (last === "index") segs.pop();
    return toUrl(segs);
  }
  return null;
}

/** Next.js app/ and pages/ routes as URL paths, sorted, deduped and capped. */
export function routesFromPaths(paths: readonly string[]): string[] {
  const routes = new Set<string>();
  for (const p of paths) {
    if (p.startsWith("node_modules/") || p.includes("/node_modules/")) continue;
    const r = routeFor(p);
    if (r) routes.add(r);
  }
  return [...routes].sort().slice(0, MAX_ROUTES);
}
