import { makeFinding } from "../../core/finding.js";
import type {
  Agent, BackendName, FileIndex, Finding, FrameworkName, SafeHttpClient, StackProfile,
} from "../../core/types.js";
import { mergeHints, type BackendHints } from "./hints.js";
import { scanLive, type LiveSignals } from "./live.js";
import { routesFromPaths } from "./routes.js";
import { scanStatic, type StaticSignals } from "./static.js";

export interface ProfileInput {
  readonly files: FileIndex;
  readonly target?: URL;
  readonly http?: SafeHttpClient;
}

const FRAMEWORK_ORDER: readonly FrameworkName[] = ["next", "vite", "react", "remix", "express"];
const BACKEND_ORDER: readonly BackendName[] = ["supabase", "firebase", "stripe", "openai", "anthropic"];

const NONE: StaticSignals & LiveSignals = { frameworks: new Set(), backends: new Set(), hints: {} };

const ordered = <T extends string>(order: readonly T[], a: ReadonlySet<T>, b: ReadonlySet<T>): T[] =>
  order.filter((x) => a.has(x) || b.has(x));

async function orEmpty<T>(work: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await work();
  } catch {
    return fallback;
  }
}

function safeRoutes(files: FileIndex, isNext: boolean): string[] {
  try {
    return isNext ? routesFromPaths(files.paths) : [];
  } catch {
    return [];
  }
}

/** Maps the stack. Runs before every other agent; its result becomes ctx.stack. Never throws. */
export async function profileStack(input: ProfileInput): Promise<StackProfile> {
  const { http, target } = input;
  const st = await orEmpty(() => scanStatic(input.files), NONE);
  const lv = http && target ? await orEmpty(() => scanLive(http, target), NONE) : NONE;
  const hints: BackendHints = mergeHints(st.hints, lv.hints);
  return {
    frameworks: ordered(FRAMEWORK_ORDER, st.frameworks, lv.frameworks),
    backends: ordered(BACKEND_ORDER, st.backends, lv.backends),
    ...hints,
    routes: safeRoutes(input.files, st.frameworks.has("next")),
  };
}

function supabaseRef(url: string): string {
  return /^https:\/\/([a-z0-9]+)\.supabase\.co/.exec(url)?.[1] ?? url;
}

export const agent: Agent = {
  id: "recon",
  name: "Recon",
  role: "Maps the stack, framework and attack surface",
  modes: ["static", "live"],
  async run(ctx): Promise<Finding[]> {
    if (ctx.mode !== "live") return [];
    const parts: string[] = [];
    if (ctx.stack.supabaseUrl) parts.push(`Supabase project ${supabaseRef(ctx.stack.supabaseUrl)}`);
    if (ctx.stack.firebaseProjectId) parts.push(`Firebase project ${ctx.stack.firebaseProjectId}`);
    if (parts.length === 0) return [];
    const label = parts.join(" and ");
    const url = ctx.target?.href;
    return [
      makeFinding({
        ruleId: "RECON-L01",
        agentId: "recon",
        title: `Backend exposed to the browser: ${label}`,
        severity: "info",
        confidence: "high",
        target: url ?? ".",
        explanation:
          `The site ships the connection details for ${label} in its public JavaScript. This is normal: the Supabase anon key ` +
          "and Firebase config are public by design, so this is not a vulnerability by itself. It does mean anyone can talk to " +
          "your backend directly, so Row Level Security (RLS) or Firebase security rules are the only real protection.",
        evidence: [{ ...(url ? { url } : {}), snippet: label }],
        fix: {
          summary: "Make sure RLS / security rules are enabled and restrictive on every table or collection.",
          agentPrompt:
            `My app exposes ${label} to the browser (expected, the anon key is public). Run \`whsquad scan\` on this project, ` +
            "then verify that RLS is enabled with restrictive policies on every table (or that Firebase security rules deny " +
            "unauthenticated access), and fix anything it reports. Never put the service_role key in client code.",
          references: [
            "https://supabase.com/docs/guides/database/postgres/row-level-security",
            "https://firebase.google.com/docs/rules",
          ],
        },
      }),
    ];
  },
};
