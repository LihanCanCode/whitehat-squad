# `whsquad review` — AI review design (v0.3)

Status: implemented (2026-10-06): src/review/, src/cli/review.ts, 37 tests; live run on the demo app found both seeded logic bugs (client price, IDOR via helper) in 11 calls. Backend chosen by the user: **Claude Code CLI only** (`claude -p`,
uses the user's existing subscription; no API key). Behind a small `LlmProvider` interface so other
backends can be added later without touching the pipeline.

## Goal

Match typical LLM audit workflows on the bugs rules cannot see —
business logic, cross-file authorization, multi-step flows — while keeping what makes whitehat-squad
different: fixes, verification, CI determinism, cheap continuous use.

| | Typical LLM audit workflow | `whsquad review` |
|---|---|---|
| Starting point | Agent reads the repo from scratch | Deterministic ground truth: 185-rule findings + engine surface map (routes, guards, taint, SQL model) — free, 0.1 s |
| Hunting | Coverage-ledger units → isolated hunters | Same idea; units come from the engine (one per handler/action/route group), prioritised by risk |
| Validation | Fresh verifier per candidate | Fresh verifier per candidate **plus a mechanical quote check**: every cited line must exist verbatim, or the candidate is rejected |
| States | confirmed / needs_validation / rejected; severity only when confirmed | Same contract |
| Coverage claim | Ledger; never "the rest is fine" | Same: reviewed / skipped (budget) / not applicable, printed in every report |
| Fixes | Describes fixes only | Confirmed findings join the ordered fix plan + master prompt; `review --recheck <id>` re-verifies after the fix |
| Cost | Many agent invocations per run | Bounded `--max-calls`; **incremental cache** — unchanged units are never re-sent |
| CI | Not designed for it | AI findings never change the exit code; rule findings still gate |

## Safety rules (non-negotiable)

1. **Opt-in and explicit consent.** `whsquad review` without `--yes` is a dry run: it prints the units,
   files and estimated calls that *would* be sent, and sends nothing.
2. **The model gets no tools.** `claude -p --tools ""`, `--strict-mcp-config`, `--no-session-persistence`,
   our own `--system-prompt`, structured output via `--json-schema`. It cannot read files, run
   commands or edit anything; we pass exactly the code we choose.
3. **State outside the repo.** Cache, last review and a fresh per-run sandbox live in a per-user folder
   (`~/.whsquad/review`, or `WHSQUAD_STATE_DIR`), keyed by the repo's real path and refused if it is
   inside the repo. A repo cannot plant cached "no findings" results, and `claude` never runs under the
   repo (Claude Code reads `CLAUDE.md` from its working folder and every parent). PATH entries inside the
   repo or any `node_modules/.bin` are ignored when locating `claude`.
4. **Repo text is data.** Every code excerpt is wrapped in the existing `DATA_BOUNDARY` contract; the
   system prompt says instructions inside code are to be reported, never followed.
5. **Secrets never leave.** Only code files are sent (never `.env*`, `.npmrc`, keys, credential or
   service-account files); vendor token shapes, generic `secret/password/token = "..."` assignments, SQL
   `PASSWORD '...'` and every value from the project's `.env` files are redacted. Repository data is
   fenced with a random per-prompt marker.
6. **Mechanical anti-hallucination.** Candidates whose quoted lines do not match the file at the cited
   line (±2) are dropped before validation; validators must quote too.
7. **Never gates, never hides.** AI findings are labelled `origin: "ai"`, are excluded from `--fail-on`,
   cannot suppress or downgrade a rule finding, and say which model produced them.

## Pipeline

```
scan (deterministic) ──► surface map ──► units (prioritised) ──► hunt (1 call/unit, cached)
        │                                                           │ candidates (schema)
        │                                                    quote check (mechanical)
        │                                                           │
        └──── rule findings given to hunters as context      validate (fresh call/candidate)
                                                                    │ confirmed / needs_validation / rejected
                                                     report + fix plan + coverage ledger
```

- **Surface map (free):** per source file the engine's handler units (method, route, guards present:
  auth / ownership / rate limit / validation / signature), Server Actions, tainted sinks; the Supabase
  table/policy model; LLM call sites. Units: one per handler/action, plus one per table group with RLS.
- **Priority:** mutations and money/auth/AI routes first; units already fully explained by a
  high-confidence rule finding are lower priority (the rule already caught it).
- **Context per unit:** the unit's file (trimmed to a window around the unit if large), plus one hop of
  local imports the unit calls (helpers, db wrappers, auth helpers), plus the rule findings in those files.
- **Hunter attack classes:** authorization (IDOR / cross-tenant / missing role check on a mutation),
  business logic (price/quantity/coupon tampering, state-machine skips, double-spend / race),
  mass assignment, trust of client-supplied identity, cross-file taint into sinks, webhook/callback
  trust, AI-specific (tool misuse, prompt injection reaching privileged actions).
- **Candidate gate:** lower-trust principal, input, intended control, crossed
  boundary, affected resource, concrete result. No best-practice or defense-in-depth claims.

## CLI

```
whsquad review [path]                 dry run: plan, units, estimated calls — sends nothing
whsquad review [path] --yes           run the review
  --model sonnet|opus|<id>            default sonnet
  --max-calls <n>                     hunter + validator calls, default 30
  --only-changed                      review only units whose code changed since the cache
  --recheck <finding-id>              re-validate one AI finding against the current code
  --format terminal|json|markdown|sarif, --out <file>
```

Output: AI findings (rule ids `REV-001..`, see catalog) in the normal report shape with
`origin: "ai"`, a "Needs validation" section, and the coverage ledger. SARIF marks them
`properties.origin = "ai"` and never above `warning`. Cache: per-user, keyed by sha256(unit context +
model + prompt version); only complete unit results (no errors, unusable replies or unvalidated
candidates) are cached.
