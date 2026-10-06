# Contributing to whitehat-squad

Thanks for helping make vibe-coded apps safer. The most valuable contributions are, in order:

1. **False-positive reports.** If `whsquad` flags something that is actually safe, open a
   [false positive issue](.github/ISSUE_TEMPLATE/false-positive.yml) with a minimal snippet. Every rule
   ships with a test proving it stays quiet on safe code — yours becomes one.
2. **Missed vulnerabilities.** A real hole it did not catch? Open a [new rule issue](.github/ISSUE_TEMPLATE/new-rule.yml).
3. **New rules and fixes.** Pick an issue labelled `good first issue`.

## Setup

```bash
git clone https://github.com/LihanCanCode/whitehat-squad.git
cd whitehat-squad
npm ci
npm run typecheck && npm test && npm run build
node bin/whsquad.js scan path/to/some/app
```

Node 20+. Zero runtime dependencies — please keep it that way.

## How a rule is built

- Each agent lives in `src/agents/<agent>/`; its rules are declared in `rules.meta.ts` (id, title,
  severity, CWE/OWASP, plain-English summary, fix). `docs/rules.md` is generated from that catalog:
  run `npx tsx scripts/gen-rules.ts` after changing it.
- Source analysis uses the shared engine in `src/core/source/` (lexer, handler units, taint,
  guards). Match on the engine's `code`/`bare` views, never on raw text, so comments and strings
  cannot trigger or hide a finding.
- Every rule needs three kinds of tests: it **fires** on the vulnerable shape, it **stays quiet**
  on the safe shape (false-positive guard), and a **control** proving the guard did not switch the
  rule off. See `tests/unit/*/` for examples.
- Findings must explain *who can exploit it and what happens* in plain English, and include a fix
  and a paste-ready `agentPrompt`.
- Regexes that run over whole files must stay linear: bounded quantifiers, no `^\s*` with the `m`
  flag. `tests/integration/hostile-input.test.ts` enforces this.

## Pull requests

- One rule or fix per PR, with tests. `npm run typecheck && npm test` must pass.
- Conventional commit messages (`feat:`, `fix:`, `docs:` ...).
- Never add a test fixture containing a real credential. Build fake tokens at runtime
  (`"sk_live_" + "x".repeat(...)` style) so secret scanners do not flag the repo.

## Security issues

Do not open a public issue for a vulnerability in whitehat-squad itself; see [SECURITY.md](SECURITY.md).
