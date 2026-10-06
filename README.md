<div align="center">

# whitehat-squad

### Your AI wrote the code. Who checked it?

**9 white-hat agents + 185 rules audit your vibe-coded app, then hand you the fix — and prove it worked.**

[![npm](https://img.shields.io/npm/v/whitehat-squad?color=brightgreen)](https://www.npmjs.com/package/whitehat-squad)
[![CI](https://github.com/LihanCanCode/whitehat-squad/actions/workflows/ci.yml/badge.svg)](https://github.com/LihanCanCode/whitehat-squad/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-2099%20passing-brightgreen)](#develop)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```bash
npx whitehat-squad scan .
```

<img src="docs/demo.gif" alt="whsquad scanning a demo app, then verifying that a database fix closed the hole" width="860">

</div>

You built something fast with Lovable, Bolt, v0, Cursor or Claude Code. It works. It is also
probably leaking something — an open database table, a key shipped to every visitor, an API route
with no auth check. These are the same handful of mistakes, over and over, across almost every
AI-generated app.

`whsquad` runs nine specialist agents and [185 deterministic rules](docs/rules.md) over your project
(or your own live site), explains each problem in plain English — what's wrong and who can exploit
it — and gives you **the fix**: an ordered fix plan, one merged SQL migration, a config snippet, or a
prompt you paste straight back into your coding agent. Then it re-checks that the hole actually
closed: **find → fix → verify**.

No Docker, no LLM key, no account. Runs offline, in seconds. Works on its own, in CI, and inside
Claude Code, Cursor and Codex.

<a id="status"></a>
> **Status: v0.3.** Deterministic checks — no LLM key is used or needed. What rules cannot judge
> (business logic, multi-file flows) is handed to *your* coding agent as a validation pack
> (`whsquad fix --format triage`) instead of being guessed at. Every rule has been
> tuned against real open-source apps to cut false positives; it is not a formal verification
> tool. **Absence of findings is not proof of security.**

---

## The squad

| Agent | Catches |
|---|---|
| **Recon** | Your stack: framework, Supabase / Firebase / Stripe / OpenAI / Anthropic usage, routes |
| **SecretsHunter** | 59 provider token formats (verified against vendor docs), committed `.env` files, secrets in `NEXT_PUBLIC_`/`VITE_` vars, optional git-history scan, keys leaked in live JS bundles |
| **DatabaseGuard** | Missing Supabase RLS, `USING (true)` policies, `SECURITY DEFINER` without a fixed `search_path`, policies that let a user grant themselves admin, `GRANT ... TO anon`, exposed views and storage buckets, open Firebase rules, a live read-only probe of whether your tables are actually readable |
| **AuthAuditor** | Unauthenticated API routes, Server Actions and Express/Hono/Fastify/Koa handlers, IDOR, JWT misuse and fallback secrets, `getSession()` or `user_metadata` used for authorization, mass assignment, Stripe price tampering, weak password hashing, debug/seed routes left open |
| **WebHardener** | Missing security headers, credentialed CORS that reflects any origin, exposed `/.git` or `/.env`, XSS sinks, unsafe upload names, wildcard image proxies, `postMessage` leaks, error details in responses |
| **SupplyChain** | Typosquats, AI-hallucinated ("slopsquat") package names, install-script risk, known-compromised versions, 29 Next.js/React framework advisories with the exact patched version, missing lockfile |
| **AIGuard** | Prompt injection, LLM output reaching `eval`/SQL/HTML, API keys shipped to the client, LLM routes with no auth or no cost cap, MCP tools that reach a shell or the file system, RAG queries without a tenant filter, uncapped agent loops |
| **InjectionHunter** | SQL injection (raw, Prisma, Supabase filter strings), MongoDB operator injection, command injection, SSRF, open redirects, path traversal, `eval` of request data — request data traced to the sink |
| **PyGuard** | FastAPI / Flask / Django: SQL and command injection, SSRF, path traversal, `pickle`/`yaml.load`, `DEBUG=True`, hardcoded secret keys, routes without auth, disabled JWT checks, fast password hashes |

Every finding ships with four things: **what's wrong**, **who can exploit it**, **the fix**
(ready-to-apply SQL / config / patch), and a **paste-ready prompt** for your coding agent — plus a
`verify` command to confirm the fix actually worked.

---

## Install

```bash
npx whitehat-squad scan .          # no install (Node 20+)
npm i -g whitehat-squad            # or install it: gives you the `whsquad` command
```

From source: `git clone https://github.com/LihanCanCode/whitehat-squad.git && cd whitehat-squad && npm ci && npm run build && npm link`.

## Quick start

```bash
whsquad scan .                                       # terminal report
whsquad scan . --format markdown --out report.md     # for a PR description
whsquad scan . --format sarif --out whsquad.sarif    # GitHub code scanning
whsquad fix .                                        # ordered fix plan (dry run)
whsquad fix . --write                                # + .gitignore lines, one SQL migration, .whsquad/fix-plan.md
whsquad verify DB-001 .                              # did my fix actually work?
whsquad explain AUTH-008                             # what a rule checks and why
```

`fix` orders the work the way an incident responder would — rotate leaked secrets, close data
exposure, then auth, injection, supply chain, AI abuse, hardening — and merges every database fix
into one migration. `--write` only ever *adds* files and lines; it never edits your source.
`--format prompt` prints one master prompt for your coding agent; `--format triage` prints the
validation pack for the cases rules can't decide.

Exit codes: `0` clean · `1` findings at or above `--fail-on` (default `high`) · `2` usage error ·
`3` live-scan ownership not verified · `4` internal error (so a crashed check never reports as
"clean").

### AI review (opt-in): the bugs rules can't see

Rules can't judge business logic. `whsquad review` adds an LLM pass for exactly that: a checkout
that trusts the price the browser sends, a "share" route that checks login but not ownership through
a helper in another file, a coupon that can be reused, an AI feature that can be steered into a
privileged action.

```bash
whsquad review .            # dry run: shows the units it would review, sends nothing
whsquad review . --yes      # run it with your Claude Code CLI (your plan, no API key)
whsquad review --recheck <id> .   # after fixing: does the independent check still find it?
```

How it works: the deterministic scan runs first and maps every route handler, Server Action and
database policy (free, offline). Each unit goes to a **hunter** with its code, one hop of local
imports and the rule findings already known; every candidate must name the attacker, the crossed
control and a concrete result. Every quoted line is **checked mechanically** against the real file —
invented code is dropped — and a **fresh validator** tries to disprove what's left
(`confirmed` / `needs validation` / rejected). Unchanged units are cached, so re-runs only pay for
what changed.

Safety rails: the model gets **no tools** (no file, shell or web access) and runs in a fresh folder
outside your repo, so a hostile `CLAUDE.md` can't steer it; its cache lives in your user folder
(`~/.whsquad/review`, or set `WHSQUAD_STATE_DIR`), so a repo can't plant results; only code files are
sent and secrets are redacted; repo text is treated as data, never instructions; `--max-calls` is a hard ceiling (default 30). AI
findings are labelled `[AI]` with the model name and **never change the exit code** — the rules
still gate CI.

| | Typical LLM audit workflows | `whsquad review` |
|---|---|---|
| Starting point | The agent reads the repo from scratch | 185-rule findings + an engine surface map, free |
| False-positive control | Independent verifier | Independent verifier **plus** a mechanical quote check |
| After a finding | Describes the fix | Fix + agent prompt + `--recheck`; joins the ordered fix plan |
| Re-runs | Full cost every time | Cached per unit; only changed code is reviewed |
| CI | Not designed for it | Advisory; the deterministic exit code is unchanged |

### Keep it running while you build

```bash
whsquad watch .
```

Re-scans on every save and prints only what's **new** or **fixed** since the last scan — run it in
a side terminal instead of waiting for a one-shot scan at the end of a session.

### Scan a live site you own (read-only)

```bash
whsquad init-proof your-app.com      # prints a one-time token
# publish it as a DNS TXT record (_whsquad.your-app.com) or at /.well-known/whsquad.txt
whsquad scan https://your-app.com
whsquad scan https://your-app.com --probe-database   # also test Supabase/Firestore tables
```

Live mode **refuses** anything you cannot prove you own (`localhost` is exempt). It can only send
`GET`/`HEAD`, stays on one hostname, and caps itself at 100 requests / 2 per second.
`--probe-database` is opt-in and reads at most one row per table — only table names, row counts
and column names are kept, never values. Full detail in [SECURITY.md](SECURITY.md).

---

## Use it from your coding agent

It's a plain CLI with exit codes and file output — nothing here is tied to one tool.

| Agent | Setup |
|---|---|
| **Claude Code** | Copy [`skills/whsquad/SKILL.md`](skills/whsquad/SKILL.md) to `.claude/skills/whsquad/` — auto-discovered. |
| **Cursor** | Copy [`templates/cursor-rules/whsquad.mdc`](templates/cursor-rules/whsquad.mdc) to `.cursor/rules/`. |
| **Codex CLI, Windsurf, or anything reading `AGENTS.md`** | Append [`templates/AGENTS.md`](templates/AGENTS.md) to your project's `AGENTS.md`. |

Once set up, ask your agent to "run a security check" — or it should do this on its own after
touching auth, a database, secrets, file uploads, or an LLM call. It scans, applies each finding's
`fix.agentPrompt`, and re-verifies with `whsquad verify`.

### In CI

Use the bundled action — it scans, uploads SARIF to the Code Scanning tab, and fails the job at
`fail-on`:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: LihanCanCode/whitehat-squad@main
    with:
      fail-on: high
      baseline: .whsquad/baseline.json   # optional: only new findings fail
```

The action ignores the scanned repo's `whsquad.config.json` by default, because on a pull request
that file is controlled by whoever opened it. Set `use-repo-config: "true"` for trusted branches.

Or copy [`examples/github-action.yml`](examples/github-action.yml) to run the CLI with `npx` directly.

### Show it off

Scanned clean? Add the badge to your README:

```markdown
[![scanned by whitehat-squad](https://img.shields.io/badge/scanned%20by-whitehat--squad-brightgreen)](https://github.com/LihanCanCode/whitehat-squad)
```

---

## When to use it

Agentic pentesting tools are built for security professionals and usually need Docker plus an LLM
API key. `whsquad` is for a different moment: the five minutes after your coding agent just wrote a
Supabase migration or an upload handler, when you want an instant, offline answer — not a 20-minute
pentest. Get a full penetration test for depth before a real launch; run this constantly, for free,
as the cheap hygiene check in between.

---

## Suppressing a finding

If a finding is a deliberate, reviewed exception, suppress it inline:

```ts
// whsquad-ignore SEC-090
const token = crypto.randomUUID(); // not a secret, just high-entropy
```

Never suppress something you haven't actually checked. Suppressions are applied centrally and
listed with `--show-suppressed`. Every report — terminal, markdown and SARIF — warns when a repo's
own `whsquad.config.json` hides findings, so a cloned repo can't quietly silence the scanner.

## Configuration

Project settings live in `whsquad.config.json` at the scan root (command-line flags win):

```json
{
  "failOn": "medium",
  "ignorePaths": ["docs/"],
  "rules": { "WEB-*": "low", "SUP-004": "off" },
  "baseline": ".whsquad/baseline.json"
}
```

`whsquad baseline .` records today's findings so later runs only fail on new ones. When auditing
code you don't trust, pass `--no-config` to ignore the repo's own settings.

---

## Develop

```bash
npm install
npm run typecheck
npm test                # 2,099 tests, 97% line coverage
npm run build
```

Contributions are very welcome — false-positive reports most of all. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the [good first issues](https://github.com/LihanCanCode/whitehat-squad/labels/good%20first%20issue).

## Roadmap

- AI review for Python (FastAPI / Flask / Django) handlers
- Cross-file taint in the deterministic engine
- SvelteKit / Remix / Nuxt route handlers; Clerk / Auth0 / Better Auth recognition
- Opt-in OSV lookups for SupplyChain
- An MCP server and a VS Code extension

Tracked as [issues](https://github.com/LihanCanCode/whitehat-squad/issues) — pick one up.

## License

[Apache-2.0](LICENSE). Use it only on systems you own or are explicitly authorized to test — see
[SECURITY.md](SECURITY.md) for the exact safety rails on live scanning.
