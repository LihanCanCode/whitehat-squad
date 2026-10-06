---
name: whsquad
description: Run the whitehat-squad security audit on the current project (leaked keys, open Supabase/Firebase databases, missing auth, unsafe LLM usage, risky dependencies), then plan the fixes, validate doubtful findings, fix in order and re-verify. Use before deploying or after vibe-coding a feature.
---

# whitehat-squad: audit, fix, verify

Use this skill when the user asks for a security check, before a deploy, or after you generated code that touches auth, a database, payments, secrets or an LLM.

## Continuous mode (optional)

While actively building, the user can keep `npx whsquad watch .` running in a side terminal. It
re-scans on every save and prints only what's new or fixed — you don't need to run it yourself,
but if a new finding appears there mid-task, treat it the same as one from `scan`.

## 1. Scan

```bash
npx whsquad scan . --format json --out whsquad-report.json
```

Exit code `1` means findings at or above the `--fail-on` threshold (default `high`). Exit code `0` means clean. Absence of findings is not proof of security; say so when you report.

## 2. Read the report

`whsquad-report.json` has `findings[]` sorted by severity. Each finding has:

- `title`, `severity`, `explanation` (plain English: who can exploit it and what happens)
- `evidence[]` (file and line, secrets redacted)
- `fix.summary`, optional `fix.sql` / `fix.config` / `fix.patch`
- `fix.agentPrompt`: the instruction for you to act on
- `verify.command`: the command that proves it is fixed

## 3. Plan the fixes

```bash
npx whsquad fix .
```

Dry run: prints an ordered fix plan (rotate leaked secrets, then data exposure, auth, injection, supply chain, AI abuse, hardening), one step per root cause, plus one merged SQL migration. `--format prompt` prints a single paste-ready prompt for the whole plan. `--write` applies only safe additive changes (.gitignore lines, one NEW Supabase migration, `.whsquad/fix-plan.md`) and never edits existing code.

## 4. Validate low and medium confidence findings first

Findings kept out of the plan (low confidence or known) and any medium-confidence ones need a second opinion before you act:

```bash
npx whsquad fix . --format triage
```

For each finding, try to DISPROVE it from the code (quote the middleware, later migration or validation that would make it safe) and answer CONFIRMED, REJECTED (with the reason) or NEEDS-HUMAN. Do not modify code during triage. Only fix CONFIRMED findings.

## 4b. Optional: AI review for logic bugs (only when the user asks for a deep review)

```bash
npx whsquad review .          # dry run: lists the units it would send
npx whsquad review . --yes    # sends them to the user's Claude Code CLI (uses their plan)
```

It finds what rules cannot: client-supplied prices, IDOR through helpers, missing role checks,
unverified webhooks. Findings are tagged `[AI]`, never change the exit code, and come with
`whsquad review --recheck <id> .` to confirm a fix. Ask before running it with `--yes`: it sends
code (secrets redacted) to the model.

## 5. Work through the steps in order

One commit per step. Rules:

- **Leaked secret:** tell the user to rotate/revoke it first. Removing it from code does not make it safe. Move it to an environment variable, never commit it.
- **Database/RLS:** write a new migration; never edit an applied one. Never "fix" an RLS error by disabling RLS or using the service-role key on the client.
- **Auth:** add the check on the server. A client-side redirect is not protection.
- If a step needs a decision only the user can make, stop and ask.
- Do not suppress a finding with `// whsquad-ignore` unless the user confirms it is a deliberate, safe exception.

## 6. Verify

```bash
npx whsquad verify <RULE-ID> .
```

Run it after each step. Report each finding as fixed, still present, or new. Do not claim the project is secure; claim only what was verified.

## Live scans

`npx whsquad scan https://their-app.example` requires proof of ownership first (`npx whsquad init-proof their-app.example`). Only run live scans against apps the user owns.
