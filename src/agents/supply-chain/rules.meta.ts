import type { RuleMeta } from "../../rules/types.js";

const AGENT = "supply-chain";
const STATIC = ["static"] as const;

/** Catalog entries for every rule this agent can raise. Keep in sync with findings.ts and findings-extra.ts. */
export const RULES: readonly RuleMeta[] = [
  {
    id: "SUP-000", agent: AGENT, title: "package.json could not be parsed", severity: "info", modes: STATIC,
    summary: "A package.json is not valid JSON, so its dependencies were not checked. npm itself would also refuse to install from it.",
    fix: "Fix the JSON syntax error without changing dependency versions, then re-run the scan.",
  },
  {
    id: "SUP-001", agent: AGENT, title: "Dependency name looks like a typosquat of a popular package", severity: "high",
    cwe: "CWE-1357", owasp: "A06", modes: STATIC, tags: ["typosquat"],
    summary: "A dependency is one typo, a look-alike character or a scope mix-up away from a popular package. Attackers register such names and wait for a mistyped or AI-suggested install; the package's install scripts then run on your machine and CI.",
    fix: "Check the spelling, install the intended package, uninstall the look-alike, and install with --ignore-scripts until verified.",
  },
  {
    id: "SUP-002", agent: AGENT, title: "Dependency name looks like an AI-hallucinated package", severity: "medium",
    cwe: "CWE-1357", owasp: "A06", modes: STATIC, tags: ["slopsquat"],
    summary: "The name follows patterns AI assistants invent (popular name plus -utils, -helpers, ...) and the lockfile has no verified registry entry for it. Attackers register hallucinated names (slopsquatting), so the package may be malware. This is a heuristic.",
    fix: "Confirm the package exists, is maintained and is what you meant (npm view); otherwise remove it and write the code yourself or use the real package.",
  },
  {
    id: "SUP-003", agent: AGENT, title: "Lifecycle script downloads or evaluates remote code", severity: "high",
    cwe: "CWE-829", owasp: "A08", modes: STATIC, tags: ["install-script"],
    summary: "One of the project's own lifecycle scripts (preinstall, install, postinstall, prepare, prepublishOnly, postpack, ...) fetches, decodes or evaluates remote code with curl, wget, node -e, eval, atob, base64 piped to a shell, or npx pkg@latest. Whoever controls the source controls every machine that installs or publishes the package.",
    fix: "Remove the remote download; vendor the file or add a pinned dependency, and install with npm ci --ignore-scripts.",
  },
  {
    id: "SUP-004", agent: AGENT, title: "Known compromised package release", severity: "critical",
    cwe: "CWE-506", owasp: "A08", modes: STATIC, tags: ["malware"],
    summary: "An exactly pinned or lockfile-resolved dependency is a release that was publicly reported as malicious or sabotaged. Secrets reachable where it was installed (npm tokens, cloud keys, .env files) should be treated as exposed.",
    fix: "Move to a clean version, delete node_modules and the lockfile entry, check npm ls for other copies, and rotate secrets present where it ran.",
  },
  {
    id: "SUP-005", agent: AGENT, title: "Dependency is not installed from a pinned registry version", severity: "medium",
    cwe: "CWE-829", owasp: "A08", modes: STATIC,
    summary: "A dependency uses a wildcard, git branch, remote tarball, unpinned GitHub shorthand or a file path outside the repository. The code behind it can change without a version bump and bypasses registry integrity checks.",
    fix: "Use an exact registry version, or pin git dependencies to a full commit hash.",
  },
  {
    id: "SUP-006", agent: AGENT, title: "Dependencies declared without a lockfile", severity: "low",
    cwe: "CWE-1357", owasp: "A06", modes: STATIC,
    summary: "No package-lock.json, pnpm-lock.yaml, yarn.lock or bun lockfile exists. Every install resolves the newest matching versions, so a malicious release published tomorrow lands in your next deploy and nothing records integrity hashes.",
    fix: "Generate and commit a lockfile and install from it with npm ci --ignore-scripts.",
  },
  {
    id: "SUP-008", agent: AGENT, title: "Auth token committed in .npmrc", severity: "critical",
    cwe: "CWE-798", modes: STATIC, tags: ["secret"],
    summary: "A registry auth token is stored in a committed .npmrc. Anyone who can read the repository, its history or build logs can publish as you or read private packages.",
    fix: "Revoke the token, replace the value with an environment variable (_authToken=${NPM_TOKEN}) and purge it from git history.",
  },
  {
    id: "SUP-009", agent: AGENT, title: "Locked dependencies run install scripts", severity: "low",
    cwe: "CWE-829", owasp: "A08", modes: STATIC, tags: ["install-script"],
    summary: "Packages in the lockfile declare install scripts that execute during npm install. Most are legitimate native builds, but install scripts are how most npm malware runs, before the package is ever imported. Informational.",
    fix: "Install with scripts disabled (npm ci --ignore-scripts, ignore-scripts=true) and rebuild only packages that need it.",
  },
  {
    id: "SUP-010", agent: AGENT, title: "Framework version with a known critical or high advisory", severity: "critical",
    cwe: "CWE-1395", owasp: "A06", modes: STATIC, tags: ["cve", "nextjs", "react-server-components"],
    summary: "The resolved (lockfile) or exactly pinned version of Next.js or a react-server-dom package lies inside the affected range of a GitHub security advisory, for example the middleware authorization bypass CVE-2025-29927 or the React Server Components remote code execution CVE-2025-55182. Severity follows the advisory and is raised or lowered by what the repo shows (middleware that performs auth, an app/ directory).",
    fix: "Upgrade to the first patched version named in the finding (npm install next@<fixed>), regenerate the lockfile and redeploy.",
  },
  {
    id: "SUP-011", agent: AGENT, title: "Dependency tracks an unstable dist-tag", severity: "medium",
    cwe: "CWE-1357", owasp: "A06", modes: STATIC,
    summary: "A dependency spec is a moving tag such as canary, beta, next, rc, alpha or experimental. It installs unreviewed builds that change without a version bump, which is also what a hijacked publish token ships first.",
    fix: "Pin a released version exactly and commit the lockfile.",
  },
  {
    id: "SUP-012", agent: AGENT, title: "overrides/resolutions point at a git, tarball or URL source", severity: "medium",
    cwe: "CWE-829", owasp: "A08", modes: STATIC,
    summary: "overrides, resolutions or pnpm.overrides replace a package everywhere in the tree with code from a git repository or remote tarball. That bypasses registry integrity checks and silently affects transitive dependencies; pinned commits are lower risk than branches or URLs.",
    fix: "Reference a published registry version or a vendored file: path instead.",
  },
  {
    id: "SUP-013", agent: AGENT, title: "Package manager config weakens registry security", severity: "medium",
    cwe: "CWE-829", owasp: "A08", modes: STATIC,
    summary: "A .npmrc, .yarnrc.yml or .yarnrc uses an http registry, disables TLS verification (strict-ssl=false, enableStrictSsl: false) or combines always-auth with a hardcoded token. Network attackers can then substitute packages.",
    fix: "Use https registry URLs, keep certificate checks on, and read tokens from environment variables.",
  },
  {
    id: "SUP-014", agent: AGENT, title: "pull_request_target workflow checks out untrusted PR code", severity: "critical",
    cwe: "CWE-94", owasp: "A08", modes: STATIC, tags: ["github-actions"],
    summary: "A workflow triggered by pull_request_target (secrets and write token) checks out the pull request head or fork and then builds it. Anyone who can open a pull request can run code with your secrets (a pwn request).",
    fix: "Use the pull_request trigger for builds, or never check out or execute PR code in the privileged workflow.",
  },
  {
    id: "SUP-015", agent: AGENT, title: "Untrusted event data interpolated into a workflow script", severity: "high",
    cwe: "CWE-94", owasp: "A08", modes: STATIC, tags: ["github-actions"],
    summary: "A run: or github-script block expands ${{ github.event... }} fields an outsider controls (titles, bodies, branch names, commit messages) straight into the script, which allows shell and script injection with the job's secrets.",
    fix: 'Pass the value through env: and use it as a quoted shell variable ("$TITLE").',
  },
  {
    id: "SUP-016", agent: AGENT, title: "Workflow grants permissions: write-all", severity: "medium",
    cwe: "CWE-1357", owasp: "A06", modes: STATIC, tags: ["github-actions"],
    summary: "write-all gives the job token every write scope, so any compromised step or dependency in the job can push code, alter releases or publish packages.",
    fix: "Declare permissions: contents: read at the top and grant extra scopes per job only where needed.",
  },
  {
    id: "SUP-017", agent: AGENT, title: "Third-party action pinned to a branch", severity: "low",
    cwe: "CWE-829", owasp: "A08", modes: STATIC, tags: ["github-actions"],
    summary: "A non-GitHub action is referenced by a branch such as @main or @master. Its owner, or anyone who compromises the account, can change what runs in your pipeline without any change in your repository.",
    fix: "Pin the action to a full commit SHA, noting the version in a comment.",
  },
  {
    id: "SUP-018", agent: AGENT, title: "Hidden Unicode in AI agent instructions", severity: "high",
    cwe: "CWE-94", owasp: "A08", modes: STATIC, tags: ["prompt-injection", "ai-agent"],
    summary: "A rules or MCP config file (.cursorrules, CLAUDE.md, AGENTS.md, copilot instructions, .mcp.json, ...) contains zero-width, bidirectional-control or Unicode tag characters. Reviewers cannot see them but coding agents read them, so they can carry hidden instructions (the rules file backdoor).",
    fix: "Remove the invisible characters, rewrite the file, and review its history for who introduced them.",
  },
  {
    id: "SUP-019", agent: AGENT, title: "MCP server launched from an unpinned package", severity: "medium",
    cwe: "CWE-829", owasp: "A08", modes: STATIC, tags: ["mcp", "ai-agent"],
    summary: "An MCP server is started with npx, bunx, uvx or pnpm dlx without a pinned version, so each launch downloads and runs the newest published code with the agent's environment and file access.",
    fix: "Pin an exact package version in args after verifying the package and publisher.",
  },
  {
    id: "SUP-020", agent: AGENT, title: "Literal credential in MCP server env", severity: "medium",
    cwe: "CWE-798", owasp: "A08", modes: STATIC, tags: ["mcp", "secret", "ai-agent"],
    summary: "An MCP config sets a *_TOKEN, *_KEY, *_SECRET or *_PASSWORD env var to a literal value that is not a recognised provider token. MCP configs are usually committed or synced, so the value spreads to every clone.",
    fix: "Rotate the credential and reference an environment variable instead of the value.",
  },
];
