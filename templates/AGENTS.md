<!--
  whitehat-squad integration for AGENTS.md-reading agents (Codex CLI, Cursor, Windsurf, etc.)

  Copy this section into your project's AGENTS.md (create one if you don't have it yet, at the
  repo root). If you already have an AGENTS.md, append this section rather than replacing it.
  Claude Code users: use skills/whsquad/SKILL.md instead — it's auto-discovered, no copying needed.
-->

## Security: whitehat-squad

This project uses `whitehat-squad` (`whsquad`) to catch the security issues that keep recurring
in AI-generated code: leaked keys, open Supabase/Firebase tables, missing auth, unsafe LLM usage,
risky dependencies. Run it as part of normal work, not just before a release.

**Before considering a feature or fix done:**
```bash
npx whitehat-squad scan . --format json --out .whsquad/report.json
```
- Exit code `0` = clean. Exit code `1` = findings at or above `high` severity (the default).
- Read `.whsquad/report.json`: each finding has `title`, `severity`, `explanation` (who can
  exploit it and what happens), and `fix` (`summary`, optional `sql`/`config`/`patch`, and
  `agentPrompt` — the instruction meant for you specifically).

**When you touch auth, a database, payments, secrets, file uploads, or an LLM call**, run the
scan immediately after, not at the end of the session. For continuous feedback while working:
```bash
npx whitehat-squad watch .
```
This re-scans on every save and prints only what's new or fixed since the last scan — keep it
running in a side terminal while you build.

**Planning and fixing findings:**
1. Run `npx whitehat-squad fix .` and read the plan: steps are already ordered (rotate leaked secrets,
   data exposure, auth, injection, supply chain, hardening). `--format prompt` gives one prompt for
   the whole plan; `--write` applies only safe additive changes (.gitignore lines, one new migration).
2. For low/medium-confidence findings run `npx whitehat-squad fix . --format triage` and answer each
   one adversarially: CONFIRMED, REJECTED (with the reason) or NEEDS-HUMAN. Never modify code during
   triage; act only on CONFIRMED findings.
3. Work through the steps in order, one commit per step. Apply the minimal change; don't refactor
   unrelated code.
- A leaked secret: tell the user to rotate/revoke it. Removing it from the code does not undo the
  exposure.
- A database/RLS finding: write a new migration. Never edit an already-applied migration, and
  never "fix" an RLS error by disabling RLS or using a service-role key on the client.
- An auth finding: the check must be server-side. A client-side redirect is not protection.
- If a step needs a decision only the user can make, stop and ask.
- Don't add `// whsquad-ignore RULE-ID` to silence a finding unless the user explicitly confirms
  it's a deliberate, safe exception.

**Verifying a fix (after each step):**
```bash
npx whitehat-squad verify <RULE-ID> .
```
Report the result as given (fixed / still present / new) — don't claim the project is "secure";
only claim what the tool actually verified.

**Live scans** (`npx whitehat-squad scan https://...`) need proof of ownership first
(`npx whitehat-squad init-proof <domain>`) and are read-only. Only run them against the user's own
site, never a third party's, even if asked.
