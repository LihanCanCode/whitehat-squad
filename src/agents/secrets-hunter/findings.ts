import { makeFinding } from "../../core/finding.js";
import type { Evidence, Finding, Severity } from "../../core/types.js";
import { DEFAULT_IMPACT } from "../../data/secret-patterns.js";
import type { RawMatch } from "./scanner.js";

export const AGENT_ID = "secrets-hunter";

const REFERENCES = [
  "https://cwe.mitre.org/data/definitions/798.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
  "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
];

export type MatchKind = "static" | "live" | "history";

export interface MatchSource {
  readonly kind: MatchKind;
  readonly target: string;
  readonly file?: string;
  readonly url?: string;
  readonly line?: number;
  readonly commit?: string;
}

function envVarName(name: string): string {
  return name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function rotationChecklist(name: string, rotateUrl: string): string {
  return [
    `Rotation checklist for: ${name}`,
    `1. Open ${rotateUrl} and revoke or roll the exposed credential NOW. Assume it is already copied.`,
    "2. Create the replacement and store it only in your hosting provider's environment settings or a secret manager.",
    "3. Read it in server-side code via process.env (never in client code, never in a NEXT_PUBLIC_/VITE_/REACT_APP_ variable).",
    "4. Redeploy so the old value stops working everywhere.",
    "5. Check the provider's usage and audit logs since the first commit/deploy that contained it for abuse.",
    "6. Remove it from git history (git filter-repo or BFG) and force-push; rotation matters more than the rewrite.",
  ].join("\n");
}

function whereText(m: RawMatch, s: MatchSource): string {
  if (s.kind === "live") return `the public page or script at ${s.url ?? s.target}`;
  const loc = s.file ? `${s.file}${s.line ? `:${s.line}` : ""}` : "your code";
  return s.kind === "history" ? `old git history (${loc}, commit ${s.commit ?? "unknown"})` : loc;
}

function ruleFor(m: RawMatch, s: MatchSource): string {
  if (s.kind === "live") return "SEC-L01";
  if (s.kind === "history") return "SEC-102";
  return m.isPublicVar && !m.isGeneric ? "SEC-101" : m.ruleId;
}

function titleFor(m: RawMatch, s: MatchSource, ruleId: string): string {
  if (ruleId === "SEC-101") return `${m.name} placed in a public browser-exposed variable`;
  if (ruleId === "SEC-102") return `${m.name} remains in git history`;
  if (ruleId === "SEC-L01") return `${m.name} exposed in the live site`;
  return m.isGeneric ? "Hardcoded high-entropy secret-like value" : `Hardcoded ${m.name}`;
}

function explanationFor(m: RawMatch, s: MatchSource, ruleId: string): string {
  const impact = m.impact ?? DEFAULT_IMPACT;
  const where = whereText(m, s);
  if (ruleId === "SEC-101") {
    return `A ${m.name} is stored in ${where} under a variable name that your build tool copies into the JavaScript bundle. Every visitor can read it from the browser, and anyone who finds it can ${impact}. Public-prefixed variables are for values meant to be public; this one is not.`;
  }
  if (ruleId === "SEC-102") {
    return `A ${m.name} was committed in ${where} and later removed, but it is still in git history. Anyone with a clone or a fork (or the public repo) can recover it and ${impact}. Deleting the line did not revoke it, so you must treat it as stolen and rotate it.`;
  }
  if (ruleId === "SEC-L01") {
    return `A ${m.name} is served to every visitor in ${where}. Anyone can open the page source, copy it and ${impact}, with no login needed. Removing it from a later build does not help until the key is rotated, because copies and caches persist.`;
  }
  if (m.isGeneric) {
    return `${where} assigns a long, random-looking string to a variable named like a key, secret, token or password. If it is a real credential, anyone who can read the code can copy it and use whatever it unlocks. This is a heuristic match, so check whether the value is real.`;
  }
  return `A ${m.name} is hardcoded in ${where}. Anyone who can read this code (teammates, contractors, GitHub if the repo is or becomes public, build logs) can copy it and ${impact}. Treat it as already leaked: deleting the line does not undo exposure, so it has to be rotated.`;
}

function evidenceFor(m: RawMatch, s: MatchSource): Evidence {
  const line = s.line ?? m.line;
  if (s.kind === "live") return { ...(s.url ? { url: s.url } : {}), line, snippet: m.snippet };
  const snippet = s.kind === "history" ? `commit ${s.commit ?? "unknown"}: ${m.snippet}` : m.snippet;
  return { ...(s.file ? { file: s.file } : {}), line, snippet };
}

function promptFor(m: RawMatch, s: MatchSource, ruleId: string): string {
  const env = envVarName(m.name);
  const place = s.kind === "live"
    ? `The deployed site at ${s.url ?? s.target} serves a ${m.name} in its public JavaScript/HTML.`
    : `${s.file ?? "A file"}${s.line ? ` line ${s.line}` : ""} contains a ${m.name}${ruleId === "SEC-102" ? " that was removed but remains in git history (commit " + (s.commit ?? "unknown") + ")" : ""}.`;
  const fix = ruleId === "SEC-101"
    ? `Rename the variable so it has no NEXT_PUBLIC_/VITE_/REACT_APP_ prefix, and move every use behind a server-side route or edge function.`
    : `Replace the literal with process.env.${env} read only in server-side code, add ${env} to a gitignored .env file and to the hosting provider's environment settings, and add a startup check that it is set.`;
  return `${place} Step 1: tell me to rotate it first at ${m.rotateUrl}, because it must be treated as compromised. Step 2: ${fix} Never log, print, echo or paste the secret value anywhere (code, console, commit messages, this chat) and do not ask me to paste the old one; refer to it only by variable name.`;
}

export function matchToFinding(m: RawMatch, s: MatchSource): Finding {
  const ruleId = ruleFor(m, s);
  const severity: Severity = ruleId === "SEC-101" ? "critical" : ruleId === "SEC-102" ? (m.severity === "medium" ? "high" : m.severity) : m.severity;
  return makeFinding({
    ruleId,
    agentId: AGENT_ID,
    title: titleFor(m, s, ruleId),
    severity,
    confidence: m.confidence,
    explanation: explanationFor(m, s, ruleId),
    evidence: [evidenceFor(m, s)],
    fix: {
      summary: `Rotate the exposed ${m.name} at ${m.rotateUrl}, then load the replacement from a server-side environment variable.`,
      agentPrompt: promptFor(m, s, ruleId),
      config: rotationChecklist(m.name, m.rotateUrl),
      references: [m.rotateUrl, ...REFERENCES],
    },
    target: s.target,
    cwe: ruleId === "SEC-101" ? "CWE-200" : "CWE-798",
  });
}

export function trackedEnvFinding(file: string, variableCount: number, target: string): Finding {
  return makeFinding({
    ruleId: "SEC-100",
    agentId: AGENT_ID,
    title: `${file} is not git-ignored`,
    severity: "high",
    explanation: `${file} normally holds real passwords and API keys, and nothing in .gitignore stops it being committed. Anyone with access to the repository (and everyone, if it is public) can read every value in it, then log in to your database, payment and AI accounts. Once committed, the values live in git history even after the file is deleted.`,
    evidence: [{ file, line: 1, snippet: `${file} is not covered by .gitignore (${variableCount} variable(s) defined)` }],
    fix: {
      summary: `Add ${file} to .gitignore, stop tracking it, and rotate every value it contains.`,
      agentPrompt: `${file} is not ignored by git. Add ".env" and ".env.*" (with an exception line "!.env.example") to .gitignore, run "git rm --cached ${file}", and commit a ${file.replace(/\.[^./]+$/, "")}.example containing variable names only with empty values. Assume every value inside ${file} is compromised: tell me which providers to rotate them at first. Never print, log or paste the values of ${file}.`,
      config: rotationChecklist(`every credential in ${file}`, "each provider's dashboard"),
      references: ["https://12factor.net/config", ...REFERENCES],
    },
    target,
    cwe: "CWE-538",
  });
}
