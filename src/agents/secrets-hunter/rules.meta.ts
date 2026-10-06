import { SECRET_PATTERNS } from "../../data/secret-patterns.js";
import type { RuleMeta } from "../../rules/types.js";

const AGENT = "secrets-hunter";

/** One entry per provider pattern, generated from the pattern table so the two can never drift. */
const PATTERN_RULES: readonly RuleMeta[] = SECRET_PATTERNS.map((p) => ({
  id: p.id,
  agent: AGENT,
  title: `Hardcoded ${p.name}`,
  severity: p.severity,
  cwe: "CWE-798",
  owasp: "A07",
  summary: `A ${p.name} is written into source or config. Anyone who can read the code can copy it and ${p.impact ?? "use your account on that service"}. Deleting the line does not undo exposure because the value stays in git history and build logs.`,
  fix: "Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.",
  modes: ["static"],
  tags: ["secrets"],
}));

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
export const RULES: readonly RuleMeta[] = [
  ...PATTERN_RULES,
  {
    id: "SEC-090", agent: AGENT, title: "High-entropy secret-like value", severity: "medium", cwe: "CWE-798", owasp: "A07",
    summary: "A long, random-looking string is assigned to a variable named like a key, secret, token or password. This is a heuristic match at low confidence; if the value is a real credential it is exposed to everyone who can read the code. Public key shapes (Firebase web keys, publishable keys) are excluded.",
    fix: "Confirm whether the value is a real credential. If so, rotate it and load it from a server-side environment variable.",
    modes: ["static"], tags: ["secrets", "heuristic"],
  },
  {
    id: "SEC-100", agent: AGENT, title: "Environment file is not git-ignored", severity: "high", cwe: "CWE-538", owasp: "A02",
    summary: "A .env file with private values is in the repository and nothing in .gitignore stops it being committed. Everyone with repository access can read every value, and committed values live on in history.",
    fix: "Add .env and .env.* (except .env.example) to .gitignore, stop tracking the file with git rm --cached, and rotate every value it contained.",
    modes: ["static"], tags: ["secrets", "env"],
  },
  {
    id: "SEC-101", agent: AGENT, title: "Secret placed in a public browser-exposed variable", severity: "critical", cwe: "CWE-200", owasp: "A02",
    summary: "A real secret is stored in a variable whose prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ and similar) makes the build tool copy it into the JavaScript bundle. Every visitor can read it from the browser.",
    fix: "Remove the public prefix, rotate the secret, and move every use behind a server-side route or edge function.",
    modes: ["static"], tags: ["secrets", "bundle"],
  },
  {
    id: "SEC-102", agent: AGENT, title: "Secret remains in git history", severity: "critical", cwe: "CWE-798", owasp: "A07",
    summary: "A credential was committed and later removed, but it is still recoverable from git history by anyone with a clone or fork. Removing the line did not revoke it.",
    fix: "Treat the secret as stolen and rotate it. Optionally rewrite history with git filter-repo or BFG; rotation matters more than the rewrite.",
    modes: ["static"], tags: ["secrets", "history"],
  },
  {
    id: "SEC-L01", agent: AGENT, title: "Secret exposed in the live site", severity: "critical", cwe: "CWE-798", owasp: "A02",
    summary: "A secret-class credential is served to every visitor in the live page or its scripts. Anyone can copy it from the page source with no login.",
    fix: "Rotate the credential immediately, remove it from the client bundle, and call the service from server-side code instead.",
    modes: ["live"], tags: ["secrets", "live"],
  },
  {
    id: "SEC-110", agent: AGENT, title: "Weak or hardcoded fallback application secret", severity: "high", cwe: "CWE-798", owasp: "A07",
    summary: "JWT_SECRET, NEXTAUTH_SECRET, AUTH_SECRET, SESSION_SECRET, COOKIE_SECRET, APP_SECRET, SECRET_KEY or ENCRYPTION_KEY is a short or well-known literal, or has a literal fallback such as process.env.JWT_SECRET || \"fallback\". Anyone who knows or guesses it can forge sessions and tokens for any user. Placeholders in .env.example are not reported.",
    fix: "Generate a random value of at least 32 bytes, keep it only in environment settings, read it with no fallback and fail at startup if it is missing.",
    modes: ["static"], tags: ["secrets", "auth"],
  },
  {
    id: "SEC-111", agent: AGENT, title: "Literal secret in compose, workflow, Dockerfile or properties file", severity: "medium", cwe: "CWE-798", owasp: "A07",
    summary: "A secret-named variable in docker-compose environment blocks, GitHub Actions env blocks, Dockerfile ENV/ARG or a .properties file holds a literal value instead of a reference. These files are committed, and Dockerfile values persist in image layers. References such as ${VAR} and ${{ secrets.X }} are not reported.",
    fix: "Reference the value by name from a secret store or gitignored .env, use build secrets in Dockerfiles, and rotate the value if it is real.",
    modes: ["static"], tags: ["secrets", "config"],
  },
  {
    id: "SEC-112", agent: AGENT, title: "Dockerfile copies the whole build context without excluding .env", severity: "medium", cwe: "CWE-538", owasp: "A05",
    summary: "A Dockerfile runs COPY . . (or ADD . .) and no .dockerignore excludes .env files, so the .env with real credentials is baked into an image layer that anyone able to pull the image can read.",
    fix: "Add a .dockerignore excluding .env, .env.*, .git and node_modules, or copy only the paths the build needs; rotate secrets if an old image was pushed.",
    modes: ["static"], tags: ["secrets", "docker"],
  },
];
