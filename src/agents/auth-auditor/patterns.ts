import { classifyPath, routeFromPath } from "../../core/source/index.js";

export const isMiddlewarePath = (p: string): boolean => classifyPath(p) === "middleware";
export const isRouteHandlerPath = (p: string): boolean => classifyPath(p) === "route";
export const isPagesApiPath = (p: string): boolean => classifyPath(p) === "pagesApi";
export const isViteConfigPath = (p: string): boolean => /(?:^|\/)vite\.config\.(?:ts|js|mjs|mts)$/.test(p);

const PUBLIC_PATH =
  /(?:^|\/)(?:health|healthz|ping|status|login|logout|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|callback|og|opengraph-image|csrf|robots|sitemap|manifest|version|available|contact|otp|verify-otp|newsletter|subscribe|unsubscribe|waitlist|feedback|\[\.\.\.nextauth\])(?:\/|\.[a-z]+$)/i;
export const isPublicByDesign = (p: string): boolean => PUBLIC_PATH.test(p);
export const isWebhookPath = (p: string): boolean => /webhook/i.test(p);

/** Calls that read or write application data. Matched on `code` (strings kept) with a real-code first character. */
export const DATA_ACCESS = new RegExp(
  [
    String.raw`\b(?:supabase\w*|admin|db|prisma|drizzle|knex|sql|firestore|pool|client|mongoose)\s*\.\s*(?:from|rpc|query|select|insert|update|delete|raw|transaction|execute|\$\w+|(?!auth\b)\w+\.(?:find\w*|create\w*|update\w*|delete\w*|upsert|count|aggregate))\b`,
    String.raw`\bsql\s*\x60`,
    String.raw`\bfetch\(\s*[\x60"']\/(?!\/)`,
  ].join("|"),
);

export const MUTATION =
  /\.(?:insert|update\w*|delete\w*|upsert|create\w*|remove|rpc|execute|\$execute\w*)\b|\b(?:insert\s+into|delete\s+from|update\s+\w+\s+set)\b/i;

/** Next.js URL of a page/route file (dynamic segments become a literal "x"), or undefined for other files. */
export function urlOfFile(path: string): string | undefined {
  const p = path.replace(/\\/g, "/");
  const api = routeFromPath(p);
  if (api !== undefined) return concrete(api);
  const page = /(?:^|\/)app\/(?:(.*)\/)?(?:page|layout)\.(?:tsx|jsx|ts|js|mjs)$/.exec(p);
  if (page) {
    const segs = (page[1] ?? "").split("/").filter((s) => s !== "" && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
    return concrete(`/${segs.join("/")}`);
  }
  const pages = /(?:^|\/)pages\/(.*)\.(?:tsx|jsx|ts|js|mjs)$/.exec(p);
  if (pages && !/^(?:_app|_document|_error|api\/)/.test(pages[1] ?? "")) {
    return concrete(`/${(pages[1] ?? "").replace(/(?:^|\/)index$/, "")}`);
  }
  return undefined;
}

function concrete(url: string): string {
  return url.replace(/\[\[?\.\.\.[^\]]+\]\]?/g, "x/y").replace(/\[[^\]]+\]/g, "x");
}

/** Server Action names that are callable by anonymous visitors by design (sign in, sign up, password recovery). */
export const PUBLIC_ACTION_NAME = /^(?:login|log_?in|log_?out|logout|sign_?in|sign_?up|sign_?out|register|forgot\w*|reset\w*pass\w*|request\w*reset\w*)$/i;
