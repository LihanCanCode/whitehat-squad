import { makeFinding } from "../../core/finding.js";
import type { Evidence, Finding } from "../../core/types.js";
import type { RiskyPackage } from "../../data/risky-packages.js";
import type { Dep } from "./manifest.js";
import type { SpecIssue } from "./spec.js";
import type { TyposquatHit } from "./names.js";

const AGENT_ID = "supply-chain";
const REF_NPM_SCRIPTS = "https://docs.npmjs.com/cli/v10/using-npm/scripts";
const REF_NPM_CI = "https://docs.npmjs.com/cli/v10/commands/npm-ci";
const REF_OWASP = "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components";
const REF_OWASP_SC = "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse";
const REF_NPM_TOKENS = "https://docs.npmjs.com/about-access-tokens";
const REF_NPMRC = "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc";

function depEvidence(file: string, dep: Dep): Evidence {
  return { file, line: dep.line, snippet: dep.text };
}

const IGNORE_SCRIPTS_NOTE = "Run installs with `npm ci --ignore-scripts` until you have verified the package.";

export function typosquatFinding(file: string, dep: Dep, hit: TyposquatHit): Finding {
  const how =
    hit.kind === "homoglyph" ? "swaps letters for look-alike digits"
    : hit.kind === "scope-confusion" ? "uses a dash where the real package has a scope slash"
    : "is one typo away from";
  const remove = `npm uninstall ${dep.name} && npm install ${hit.target}`;
  return makeFinding({
    ruleId: "SUP-001",
    agentId: AGENT_ID,
    title: `"${dep.name}" looks like a typosquat of "${hit.target}"`,
    severity: "high",
    confidence: "medium",
    explanation:
      `Your dependency "${dep.name}" ${how} the popular package "${hit.target}". Attackers register ` +
      `misspelled names and wait for a typo, or for an AI assistant to suggest one. When you run npm install, ` +
      `the package's install scripts execute on your laptop and in your CI with access to your environment variables, ` +
      `tokens and SSH keys. If you meant "${hit.target}", you are installing a stranger's code instead.`,
    evidence: [depEvidence(file, dep)],
    fix: {
      summary: `Check the spelling. If you meant "${hit.target}": ${remove}. Otherwise review the package page before keeping it. ${IGNORE_SCRIPTS_NOTE}`,
      config: remove,
      agentPrompt:
        `In ${file}, the dependency "${dep.name}" looks like a typosquat of "${hit.target}". Verify which package the code ` +
        `really imports (search for "${dep.name}" in the source). If it should be "${hit.target}", run \`${remove}\`, ` +
        `fix every import, then run \`npm ci --ignore-scripts\` and the tests. If "${dep.name}" is intentional, ` +
        `confirm its publisher and download count on npmjs.com and pin an exact version.`,
      references: [REF_OWASP_SC, "https://docs.npmjs.com/threats-and-mitigations"],
    },
    target: file,
    cwe: "CWE-1357",
  });
}

export function slopFinding(file: string, dep: Dep, base: string, hasLock: boolean): Finding {
  return makeFinding({
    ruleId: "SUP-002",
    agentId: AGENT_ID,
    title: `"${dep.name}" may be an AI-hallucinated package name`,
    severity: "medium",
    confidence: "low",
    explanation:
      `"${dep.name}" follows a naming pattern AI coding assistants often invent ("${base}" plus a suffix like -utils or -helpers) ` +
      `and is not a package we recognise. Attackers watch for these hallucinated names and register them on npm ("slopsquatting"), ` +
      `so a name the AI made up can become real malware. ${hasLock ? "The lockfile has no verified registry entry for it." : "There is no lockfile pinning what was actually installed."} ` +
      `npm install runs the package's code on your machine and your CI. This is a heuristic, so check before acting.`,
    evidence: [depEvidence(file, dep)],
    fix: {
      summary: `Confirm the package exists, is maintained, and is what you meant (npm view ${dep.name}). If not: npm uninstall ${dep.name}`,
      config: `npm view ${dep.name} time.created maintainers dist.tarball\nnpm uninstall ${dep.name}`,
      agentPrompt:
        `The dependency "${dep.name}" in ${file} may have been hallucinated by an AI assistant. Check whether the code really ` +
        `needs it. If the functionality can come from "${base}" itself or a few lines of code, remove it with ` +
        `\`npm uninstall ${dep.name}\` and rewrite the imports. If it is genuine, run \`npm view ${dep.name}\`, check the ` +
        `publisher, creation date and weekly downloads, then pin an exact version and commit the lockfile.`,
      references: [REF_OWASP_SC, "https://docs.npmjs.com/threats-and-mitigations"],
    },
    target: file,
    cwe: "CWE-1357",
  });
}

export function ownInstallScriptFinding(file: string, hook: string, command: string, line: number, when: "install" | "publish" = "install"): Finding {
  return makeFinding({
    ruleId: "SUP-003",
    agentId: AGENT_ID,
    title: `package.json "${hook}" script downloads or evaluates remote code`,
    severity: when === "install" ? "high" : "medium",
    explanation:
      `The "${hook}" script runs automatically ${when === "install" ? "on every npm install, for you, your teammates and CI" : "when the package is packed or published, with your npm credentials in reach"}. It fetches, decodes or evaluates ` +
      `something from the network, so whoever controls that URL controls your machine. This is the exact trick used by ` +
      `npm malware to steal environment variables, SSH keys and cloud credentials.`,
    evidence: [{ file, line, snippet: `"${hook}": "${command}"` }],
    fix: {
      summary: `Remove the remote download from "${hook}". Vendor the file, add it as a pinned dependency, and install with npm ci --ignore-scripts.`,
      config: "npm ci --ignore-scripts",
      agentPrompt:
        `In ${file}, the "${hook}" script runs \`${command}\`, which executes remote code at install time. Remove it, replace it ` +
        `with a checked-in script or a pinned dependency, and confirm \`npm ci --ignore-scripts\` still produces a working build.`,
      references: [REF_NPM_SCRIPTS, REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-829",
  });
}

export function dependencyScriptsFinding(lockFile: string, names: readonly string[]): Finding {
  const shown = names.slice(0, 15).join(", ") + (names.length > 15 ? `, and ${names.length - 15} more` : "");
  return makeFinding({
    ruleId: "SUP-009",
    agentId: AGENT_ID,
    title: `${names.length} locked dependenc${names.length === 1 ? "y runs" : "ies run"} install scripts`,
    severity: "low",
    confidence: "low",
    explanation:
      `These packages execute code during npm install: ${shown}. Most are legitimate (native builds), but install scripts are how ` +
      `most npm malware runs, before you ever import the package. This is informational; it is a reason to install with scripts disabled by default.`,
    evidence: [{ file: lockFile, snippet: names.slice(0, 5).join(", ") }],
    fix: {
      summary: "Install with scripts disabled and allow only what needs them: npm ci --ignore-scripts",
      config: "npm ci --ignore-scripts\nnpm config set ignore-scripts true",
      agentPrompt:
        `Make this project install safely: set \`ignore-scripts=true\` in .npmrc, use \`npm ci --ignore-scripts\` in CI, and run ` +
        `\`npm rebuild <pkg>\` only for packages that truly need a build step (${shown}).`,
      references: [REF_NPM_SCRIPTS, REF_NPM_CI],
    },
    target: lockFile,
    cwe: "CWE-829",
  });
}

export function riskyFinding(file: string, name: string, version: string, advisory: RiskyPackage, evidence: Evidence): Finding {
  return makeFinding({
    ruleId: "SUP-004",
    agentId: AGENT_ID,
    title: `${name}@${version} is a known compromised release`,
    severity: "critical",
    explanation:
      `${name}@${version} was publicly reported as malicious or sabotaged (${advisory.reason}). If this version was ever installed, ` +
      `assume secrets reachable from that machine or CI run (npm tokens, cloud keys, .env files) are exposed and rotate them.`,
    evidence: [evidence],
    fix: {
      summary: `Move off this version now: npm install ${name}@latest, delete node_modules and the lockfile entry, then rotate any secrets present where it ran.`,
      config: `npm install ${name}@latest\nnpm ls ${name}\nnpm ci --ignore-scripts`,
      agentPrompt:
        `${name}@${version} (in ${file}) is a known compromised release: ${advisory.reason}. Upgrade or pin ${name} to a safe version ` +
        `with \`npm install ${name}@latest\`, make sure no other package pulls ${version} (\`npm ls ${name}\`), regenerate the lockfile, ` +
        `and list which secrets I must rotate.`,
      references: ["https://github.com/advisories", REF_OWASP],
    },
    target: file,
    cwe: "CWE-506",
  });
}

export function specFinding(file: string, dep: Dep, issue: SpecIssue): Finding {
  const pin = issue.kind === "wildcard" ? `npm install ${dep.name}@<exact version> --save-exact` : `npm install ${dep.name}@<registry version> --save-exact`;
  return makeFinding({
    ruleId: "SUP-005",
    agentId: AGENT_ID,
    title: `"${dep.name}" is not installed from a pinned registry version`,
    severity: "medium",
    explanation:
      `${issue.detail}. A dependency like this can change under you: whoever controls the URL, repo branch or the "latest" tag ` +
      `can ship different code on the next npm install, and it bypasses the registry's integrity checks. A hijacked or ` +
      `rewritten source then runs on your machine and in CI.`,
    evidence: [depEvidence(file, dep)],
    fix: {
      summary: `Use a registry release pinned to an exact version (${pin}), or pin git dependencies to a full commit hash.`,
      config: pin,
      agentPrompt:
        `In ${file}, "${dep.name}": "${dep.spec}" is not pinned (${issue.detail}). Replace it with an exact published version ` +
        `from the npm registry (or a full 40-character commit hash for git dependencies), then regenerate the lockfile and run \`npm ci --ignore-scripts\`.`,
      references: ["https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies", REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-829",
  });
}

export function noLockfileFinding(file: string, line: number): Finding {
  return makeFinding({
    ruleId: "SUP-006",
    agentId: AGENT_ID,
    title: "Dependencies are declared but there is no lockfile",
    severity: "low",
    explanation:
      `Without package-lock.json, pnpm-lock.yaml or yarn.lock, every install resolves the newest version matching your ranges. ` +
      `A compromised or typosquatted release published tomorrow is installed automatically on your next deploy, and nothing records integrity hashes to catch tampering.`,
    evidence: [{ file, line, snippet: `"dependencies": { ... }` }],
    fix: {
      summary: "Generate and commit a lockfile, then install from it with npm ci --ignore-scripts.",
      config: "npm install --package-lock-only\ngit add package-lock.json",
      agentPrompt:
        `Create and commit a lockfile for ${file} (\`npm install --package-lock-only\`), make sure it is not in .gitignore, ` +
        `and change CI and the deploy to use \`npm ci --ignore-scripts\`.`,
      references: [REF_NPM_CI, REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-1357",
  });
}

export function npmrcTokenFinding(file: string, line: number, redactedSnippet: string): Finding {
  return makeFinding({
    ruleId: "SUP-008",
    agentId: AGENT_ID,
    title: "npm auth token committed in .npmrc",
    severity: "critical",
    explanation:
      `${file} contains a registry auth token. Anyone who can read the repository (or its history, forks and build logs) can publish ` +
      `packages as you or read your private packages; stolen npm tokens are how maintainers' packages get backdoored. Revoke it first, then remove it.`,
    evidence: [{ file, line, snippet: redactedSnippet }],
    fix: {
      summary: "Revoke the token on npmjs.com, replace the value with an environment variable (_authToken=${NPM_TOKEN}), and remove it from git history.",
      config: "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
      agentPrompt:
        `${file} has a hardcoded npm auth token on line ${line}. Replace the value with \`\${NPM_TOKEN}\`, add the real token to the CI secret store, ` +
        `tell me to revoke the leaked token at npmjs.com (Access Tokens), and remind me to purge it from git history.`,
      references: [REF_NPM_TOKENS, REF_NPMRC],
    },
    target: file,
    cwe: "CWE-798",
  });
}

export function unreadableFinding(file: string): Finding {
  return makeFinding({
    ruleId: "SUP-000",
    agentId: AGENT_ID,
    title: `${file} could not be parsed`,
    severity: "info",
    explanation: `${file} is not valid JSON, so its dependencies were not checked. Fix the syntax error so the supply-chain checks can run (npm install would also fail).`,
    evidence: [{ file, snippet: "invalid JSON" }],
    fix: {
      summary: "Validate the file with: node -e \"JSON.parse(require('fs').readFileSync('package.json','utf8'))\"",
      agentPrompt: `Fix the JSON syntax error in ${file} without changing any dependency versions.`,
      references: ["https://docs.npmjs.com/cli/v10/configuring-npm/package-json"],
    },
    target: file,
  });
}
