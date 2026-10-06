import { makeFinding } from "../../core/finding.js";
import type { Confidence, Finding } from "../../core/types.js";
import { AGENT_ID } from "./findings.js";
import { LITERAL_SECRET_RULE_ID, WEAK_SECRET_RULE_ID, type ConfigSecretMatch } from "./config-secrets.js";
import { DOCKER_CONTEXT_RULE_ID, type ContextCopy } from "./docker-context.js";

const CWE_798 = "https://cwe.mitre.org/data/definitions/798.html";
const SECRETS_CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html";
const DOCKERIGNORE_DOCS = "https://docs.docker.com/build/concepts/context/#dockerignore-files";
const GENERATE_HINT = 'Generate a real one with `openssl rand -base64 48` (never reuse an example value).';

function weakWhy(m: ConfigSecretMatch): string {
  if (m.fallback) {
    return `has a literal fallback (\`process.env.${m.name} || "..."\`). If the variable is ever unset (a new environment, a typo, a failed deploy) the app silently signs sessions with a value that is sitting in the repository`;
  }
  if (m.reason === "known-default") return "is set to a well-known default value that attackers try first";
  return `is a short literal (${m.value.length} characters) that can be brute-forced or guessed`;
}

export function weakSecretFinding(m: ConfigSecretMatch, file: string, target: string): Finding {
  return makeFinding({
    ruleId: WEAK_SECRET_RULE_ID,
    agentId: AGENT_ID,
    title: m.fallback ? `${m.name} has a hardcoded fallback secret` : `${m.name} is a weak literal secret`,
    severity: "high",
    confidence: m.confidence,
    explanation: `${m.name} in ${file}:${m.line} ${weakWhy(m)}. This value signs or encrypts sessions, tokens or cookies, so anyone who knows or guesses it can forge a login as any user, including an admin, without ever knowing a password.`,
    evidence: [{ file, line: m.line, snippet: m.snippet }],
    fix: {
      summary: `Replace ${m.name} with a long random value stored only in the hosting provider's environment settings, and fail at startup if it is missing.`,
      agentPrompt: `${file} line ${m.line} gives ${m.name} a weak or hardcoded value. Remove the literal, read ${m.name} only from process.env with no fallback, and throw at startup when it is missing or shorter than 32 characters. Generate a new random value (at least 32 bytes, for example \`openssl rand -base64 48\`), store it in the hosting provider's environment settings and in a gitignored .env file, and redeploy. Rotating it signs every user out, which is expected. Never print, log or paste the secret value; refer to it by variable name only.`,
      config: [`1. ${GENERATE_HINT}`, `2. Set ${m.name} in your hosting provider's environment settings and your gitignored .env.`, `3. Read it without a fallback: const secret = process.env.${m.name}; if (!secret || secret.length < 32) throw new Error("${m.name} is not configured");`, "4. Redeploy. Existing sessions are invalidated, which is the point."].join("\n"),
      references: [CWE_798, SECRETS_CHEATSHEET],
    },
    target,
    cwe: "CWE-798",
  });
}

export function literalSecretFinding(m: ConfigSecretMatch, file: string, target: string): Finding {
  return makeFinding({
    ruleId: LITERAL_SECRET_RULE_ID,
    agentId: AGENT_ID,
    title: `${m.name} is a literal secret in ${file}`,
    severity: "medium",
    confidence: m.confidence,
    explanation: `${file}:${m.line} sets ${m.name} to a literal value that looks like a real credential. Anyone who can read this file (the repository, CI logs, and for a Dockerfile ENV/ARG every person who can pull the image) can copy it. Config files like this are usually committed, so treat the value as exposed. This is a heuristic match: check whether the value is real.`,
    evidence: [{ file, line: m.line, snippet: m.snippet }],
    fix: {
      summary: `Move ${m.name} out of ${file} into a secret store and reference it by name instead of by value.`,
      agentPrompt: `${file} line ${m.line} sets ${m.name} to a literal value. Replace it with a reference (\`\${${m.name}}\` in docker-compose, \`\${{ secrets.${m.name} }}\` in GitHub Actions, a runtime --mount=type=secret or an env var in a Dockerfile) and keep the real value only in a secret store or gitignored .env. If it is a real credential, rotate it first, because it is already exposed. Never print, log or paste the value; refer to it by variable name only.`,
      config: ["1. Rotate the credential if it is real; assume it is already copied.", `2. Store the new value in your CI/hosting secret store as ${m.name}.`, "3. Reference it by name in the file; never inline the value.", "4. For Dockerfiles use build secrets (RUN --mount=type=secret) instead of ENV/ARG, which persist in image layers."].join("\n"),
      references: [CWE_798, SECRETS_CHEATSHEET],
    },
    target,
    cwe: "CWE-798",
  });
}

export function dockerContextFinding(copy: ContextCopy, file: string, confidence: Confidence, target: string): Finding {
  return makeFinding({
    ruleId: DOCKER_CONTEXT_RULE_ID,
    agentId: AGENT_ID,
    title: `${file} copies the whole build context and nothing keeps .env out`,
    severity: "medium",
    confidence,
    explanation: `${file}:${copy.line} runs \`${copy.snippet}\`, which copies everything in the build context into the image, and there is no .dockerignore that excludes .env files. Your .env (with database passwords and API keys) is baked into an image layer, so anyone who can pull the image, or any registry leak, hands over every secret even if you delete the file in a later step.`,
    evidence: [{ file, line: copy.line, snippet: copy.snippet }],
    fix: {
      summary: "Add a .dockerignore that excludes .env* (and .git, node_modules), or copy only the files the build needs.",
      agentPrompt: `${file} line ${copy.line} copies the whole build context. Create or update the .dockerignore next to it with the lines ".env", ".env.*", "!.env.example", ".git" and "node_modules", or replace the copy with explicit paths (package files first, then src). Assume any image built before this fix contains the secrets from .env: tell me which providers to rotate them at. Never print, log or paste values from .env.`,
      config: ["1. Create .dockerignore next to the Dockerfile with: .env, .env.*, !.env.example, .git, node_modules", "2. Rebuild the image and confirm: docker run --rm IMAGE ls -a /app should show no .env", "3. Rotate every value that was in .env if an old image was ever pushed to a registry."].join("\n"),
      references: [DOCKERIGNORE_DOCS, "https://cwe.mitre.org/data/definitions/538.html"],
    },
    target,
    cwe: "CWE-538",
  });
}
