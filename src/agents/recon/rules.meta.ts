import type { RuleMeta } from "../../rules/types.js";

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
export const RULES: readonly RuleMeta[] = [
  {
    id: "RECON-L01",
    agent: "recon",
    title: "Backend exposed to the browser",
    severity: "info",
    cwe: "CWE-200",
    owasp: "A05",
    summary:
      "The site ships connection details for a Supabase or Firebase backend in its public JavaScript. This is normal because anon keys and Firebase config are public by design, but it means anyone can talk to the backend directly, so RLS or security rules are the only real protection.",
    fix: "Make sure Row Level Security or Firebase security rules are enabled and restrictive on every table or collection, and never ship the service_role key.",
    modes: ["live"],
    tags: ["recon", "supabase", "firebase"],
  },
];
