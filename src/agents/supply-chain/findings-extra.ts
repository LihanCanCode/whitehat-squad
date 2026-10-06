import { makeFinding } from "../../core/finding.js";
import type { Finding } from "../../core/types.js";
import type { HiddenText, McpServer, UnpinnedLauncher } from "./agent-config.js";
import type { Dep, OverrideEntry } from "./manifest.js";
import type { ConfigIssue } from "./package-config.js";
import type { DistTagIssue, SourceSpec } from "./spec.js";
import type { WorkflowIssue } from "./workflows.js";

const AGENT_ID = "supply-chain";
const REF_OWASP_SC = "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse";
const REF_NPM_OVERRIDES = "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#overrides";
const REF_NPMRC = "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc";
const REF_GHA_SECURITY = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions";
const REF_PWN_REQUESTS = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/";
const REF_MCP = "https://modelcontextprotocol.io/docs/concepts/architecture";

export function distTagFinding(file: string, dep: Dep, issue: DistTagIssue): Finding {
  const pin = `npm install ${dep.name}@<exact version> --save-exact`;
  return makeFinding({
    ruleId: "SUP-011",
    agentId: AGENT_ID,
    title: `"${dep.name}" tracks the "${issue.tag}" dist-tag`,
    severity: issue.severity,
    explanation:
      `"${dep.name}": "${dep.spec}" installs whatever the maintainers last published under the "${issue.tag}" tag. ` +
      `Those builds are unreviewed, change without a version bump, and are exactly what an attacker with a stolen publish token ships first. ` +
      `Every install, including CI and deploys without a lockfile, can pull different code.`,
    evidence: [{ file, line: dep.line, snippet: dep.text }],
    fix: {
      summary: `Pin a released version instead of the "${issue.tag}" tag: ${pin}.`,
      config: pin,
      agentPrompt:
        `In ${file}, "${dep.name}" uses the "${issue.tag}" dist-tag. Run \`npm view ${dep.name} dist-tags versions\`, choose a stable release, ` +
        `pin it exactly, regenerate the lockfile and run the tests.`,
      references: [REF_OWASP_SC, "https://docs.npmjs.com/cli/v10/commands/npm-dist-tag"],
    },
    target: file,
    cwe: "CWE-1357",
  });
}

export function overrideFinding(file: string, entry: OverrideEntry, source: SourceSpec): Finding {
  const pinned = source.kind === "git" && source.pinned;
  return makeFinding({
    ruleId: "SUP-012",
    agentId: AGENT_ID,
    title: `${entry.source} replaces "${entry.name}" with a ${source.kind === "tarball" ? "remote tarball" : "git source"}`,
    severity: pinned ? "low" : "medium",
    explanation:
      `${entry.source} forces every copy of "${entry.name}" in your dependency tree to come from "${entry.spec}" instead of the npm registry. ` +
      `${pinned ? "It is pinned to a commit, but it" : "Whoever controls that URL or branch can change the code at any time, and it"} bypasses registry integrity checks and ` +
      `silently affects transitive dependencies you never reviewed.`,
    evidence: [{ file, line: entry.line, snippet: entry.text }],
    fix: {
      summary: `Point ${entry.source} at a published registry version, or vendor the patched package and reference it with file:.`,
      config: `npm install ${entry.name}@<patched version>`,
      agentPrompt:
        `In ${file}, ${entry.source} sets "${entry.name}" to "${entry.spec}". Replace it with an exact registry version (or a vendored file: path), ` +
        `regenerate the lockfile and run \`npm ci --ignore-scripts\` and the tests.`,
      references: [REF_NPM_OVERRIDES, REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-829",
  });
}

export function packageConfigFinding(file: string, issue: ConfigIssue): Finding {
  return makeFinding({
    ruleId: "SUP-013",
    agentId: AGENT_ID,
    title: `${file}: ${issue.what}`,
    severity: "medium",
    explanation:
      `${file} line ${issue.line} (${issue.snippet}) weakens how packages are downloaded. Over plain http or without certificate checks, ` +
      `anyone on the network path (a shared Wi-Fi, a compromised proxy) can swap a package for malware, and the lockfile hashes only help if they were generated honestly.`,
    evidence: [{ file, line: issue.line, snippet: issue.snippet }],
    fix: {
      summary: "Use an https registry URL, leave certificate checking on, and keep tokens in environment variables.",
      config: "registry=https://registry.npmjs.org/\nstrict-ssl=true",
      agentPrompt:
        `In ${file} line ${issue.line}: ${issue.what}. Switch the registry to https, remove any strict-ssl=false / enableStrictSsl: false, ` +
        `and if the registry uses a private CA set cafile instead of disabling verification.`,
      references: [REF_NPMRC, REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-829",
  });
}

export function workflowFinding(file: string, issue: WorkflowIssue): Finding {
  const base = { agentId: AGENT_ID, evidence: [{ file, line: issue.line, snippet: issue.snippet }], target: file } as const;
  switch (issue.rule) {
    case "SUP-014":
      return makeFinding({
        ...base, ruleId: "SUP-014", severity: "critical", cwe: "CWE-94",
        title: "pull_request_target workflow checks out untrusted pull request code",
        explanation:
          `This workflow runs on pull_request_target, which has write access and secrets, and then ${issue.detail}. Anyone who can open a pull request ` +
          `can put code in the branch that the next step (npm install, build, test) executes with your repository secrets and a write-scoped GITHUB_TOKEN. ` +
          `This is the classic "pwn request" that leaks tokens and lets attackers push to your repo.`,
        fix: {
          summary: "Do not check out the PR head in a pull_request_target job. Use the pull_request trigger for builds, or split into an unprivileged build and a privileged workflow that never runs PR code.",
          config: "on: pull_request   # no secrets, read-only token; check out the default merge ref",
          agentPrompt:
            `In ${file} line ${issue.line}, the workflow is triggered by pull_request_target and checks out the pull request head. Change the trigger to pull_request, ` +
            `or remove the ref/repository override so only the base branch is checked out, and never run npm install or scripts from PR code with secrets.`,
          references: [REF_PWN_REQUESTS, REF_GHA_SECURITY],
        },
      });
    case "SUP-015":
      return makeFinding({
        ...base, ruleId: "SUP-015", severity: "high", cwe: "CWE-94",
        title: "Untrusted GitHub event data is interpolated into a workflow script",
        explanation:
          `${issue.detail} is expanded into the script text before the shell runs. A pull request title, branch name, issue body or commit message ` +
          `containing backticks or $(...) becomes commands on the runner, with access to the job's secrets and token.`,
        fix: {
          summary: 'Pass the value through env: and reference it as a quoted shell variable ("$TITLE"), never as ${{ ... }} inside run:.',
          config: 'env:\n  TITLE: ${{ github.event.pull_request.title }}\nrun: echo "$TITLE"',
          agentPrompt:
            `In ${file} line ${issue.line}, ${issue.detail} is used inside a run/script block. Move it to an env: variable on the step and use "$VAR" in the script ` +
            `(or process.env.VAR in github-script).`,
          references: [REF_GHA_SECURITY, "https://securitylab.github.com/resources/github-actions-untrusted-input/"],
        },
      });
    case "SUP-016":
      return makeFinding({
        ...base, ruleId: "SUP-016", severity: "medium", cwe: "CWE-1357",
        title: "Workflow grants permissions: write-all",
        explanation:
          "write-all gives the job's GITHUB_TOKEN write access to contents, packages, actions, pull requests and more. Any compromised step or dependency " +
          "run in that job can push code, tamper with releases or publish packages.",
        fix: {
          summary: "Declare least privilege: permissions: contents: read at the top, and grant extra scopes only to the jobs that need them.",
          config: "permissions:\n  contents: read",
          agentPrompt: `In ${file} line ${issue.line} replace "permissions: write-all" with the minimum scopes each job needs, starting from "contents: read".`,
          references: [REF_GHA_SECURITY, "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token"],
        },
      });
    default:
      return makeFinding({
        ...base, ruleId: "SUP-017", severity: "low", cwe: "CWE-829",
        title: `Third-party action "${issue.detail}" is pinned to a branch`,
        explanation:
          `A branch name is a moving target: the owner of ${issue.detail.split("@")[0]} (or anyone who compromises their account) can change what runs in your pipeline ` +
          `with access to your secrets, without any change in your repository.`,
        fix: {
          summary: "Pin the action to a full commit SHA (with the version in a comment), or at least to a release tag.",
          config: "uses: owner/action@<full 40-character commit sha> # v1.2.3",
          agentPrompt: `In ${file} line ${issue.line}, pin ${issue.detail} to the full commit SHA of its latest release and add the version as a comment.`,
          references: [REF_GHA_SECURITY, REF_OWASP_SC],
        },
      });
  }
}

export function hiddenTextFinding(file: string, hit: HiddenText): Finding {
  const snippet =
    `${hit.count} invisible character${hit.count === 1 ? "" : "s"} (${hit.codepoints.join(", ")})` +
    (hit.decoded ? `; hidden text decodes to: "${hit.decoded.replace(/[^\x20-\x7e]/g, "?")}"` : "");
  return makeFinding({
    ruleId: "SUP-018",
    agentId: AGENT_ID,
    title: `${file} contains hidden Unicode instructions for your coding agent`,
    severity: "high",
    explanation:
      `${file} contains ${hit.count} invisible or bidirectional-control character${hit.count === 1 ? "" : "s"}, first on line ${hit.line}. Humans reviewing the file ` +
      `cannot see them, but a coding agent (Cursor, Claude Code, Copilot, Cline) reads them as text, so they can carry hidden instructions such as "add this dependency" or ` +
      `"send the .env file here". This "rules file backdoor" is a known prompt-injection technique, often introduced through a copied rules file or a pull request.`,
    evidence: [{ file, line: hit.line, snippet }],
    fix: {
      summary: "Delete every invisible character from the file, re-type any suspicious line, and review the file's git history for who added it.",
      config: `grep -nP "[\\x{200B}-\\x{200F}\\x{2060}-\\x{2064}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{E0000}-\\x{E007F}]" ${file}`,
      agentPrompt:
        `${file} contains invisible Unicode characters (${hit.codepoints.join(", ")}) starting on line ${hit.line}. Rewrite the file with those characters removed, ` +
        `tell me what any decoded hidden text said, and check recent commits touching it for instructions that add dependencies, URLs or credentials.`,
      references: ["https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents", REF_MCP],
    },
    target: file,
    cwe: "CWE-94",
  });
}

export function unpinnedMcpFinding(file: string, line: number, server: McpServer, launch: UnpinnedLauncher): Finding {
  return makeFinding({
    ruleId: "SUP-019",
    agentId: AGENT_ID,
    title: `MCP server "${server.name}" runs an unpinned package via ${launch.runner}`,
    severity: "medium",
    explanation:
      `The MCP server "${server.name}" is started with \`${launch.runner} ${launch.spec}\` without a fixed version, so every launch downloads and runs the newest ` +
      `published code with your agent's permissions, your environment variables and often your files. A hijacked or typosquatted package becomes code execution on your machine the next time the agent starts.`,
    evidence: [{ file, line, snippet: `"${server.name}": ${server.command ?? ""} ${server.args.join(" ")}`.trim() }],
    fix: {
      summary: `Pin the exact version in the args, e.g. ${launch.spec.replace(/@[^@/]*$/, "")}@<version>, after checking the package and its publisher.`,
      config: `"args": ["-y", "${launch.spec.replace(/@[^@/]*$/, "")}@<exact version>"]`,
      agentPrompt:
        `In ${file}, the MCP server "${server.name}" is launched via ${launch.runner} without a pinned version. Look up the package on its registry, confirm the publisher, ` +
        `and pin the exact current version in args.`,
      references: [REF_MCP, REF_OWASP_SC],
    },
    target: file,
    cwe: "CWE-829",
  });
}

export function mcpSecretFinding(file: string, line: number, server: McpServer, envName: string, redacted: string): Finding {
  return makeFinding({
    ruleId: "SUP-020",
    agentId: AGENT_ID,
    title: `MCP server "${server.name}" has a literal value for ${envName}`,
    severity: "medium",
    explanation:
      `${file} stores a literal credential in the env of the MCP server "${server.name}". MCP config files are usually committed or synced, so the value ends up ` +
      `in git history and on every machine that clones the repo. Treat it as exposed and rotate it.`,
    evidence: [{ file, line, snippet: `"${envName}": "${redacted}"` }],
    fix: {
      summary: "Rotate the credential, reference an environment variable instead of the value, and keep the real value in your shell or secret store.",
      config: `"env": { "${envName}": "\${env:${envName}}" }`,
      agentPrompt:
        `${file} has a hardcoded value for ${envName} in MCP server "${server.name}". Replace it with an environment-variable reference supported by the client, ` +
        `remind me to rotate the credential, and make sure the file does not contain the old value in git history.`,
      references: [REF_MCP, "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
    },
    target: file,
    cwe: "CWE-798",
  });
}
