# Security Policy

whitehat-squad is a **defensive** tool. It exists to help you find and fix holes in apps **you own or are authorized to test**.

## Responsible use

- Live scans (`whsquad scan https://...`) only run against targets whose ownership you prove (DNS TXT record or `/.well-known/whsquad.txt`), plus `localhost`. Do not try to bypass this check.
- Live mode is read-only: the HTTP client can only send `GET`/`HEAD`, never `POST`/`PUT`/`DELETE`. It makes at most 100 requests per scan, at 2 requests per second, and stays on the target's hostname.
- Database probes (`DB-L01`, `DB-L02`) only run with `--probe-database`. They read at most one row per table and record only table names, row counts and column names. Row values are discarded.
- Secrets found are redacted in every report (first 4 / last 4 characters).

Never scan systems you do not own or have written permission to test.

## Reporting a vulnerability in whitehat-squad

Please open a private security advisory on the GitHub repository (Security tab -> "Report a vulnerability") instead of a public issue. Include steps to reproduce and the affected version. Expect an acknowledgement within a few days.

Areas of particular interest: SSRF-guard bypasses, ownership-verification bypasses, anything that makes the HTTP client send a non-read-only request, and any path where a raw secret reaches a report.

## Known limitations (v0.2)

From the internal security review. None allows the live client to send a write request or leave the target host; they are hardening items tracked for the next release:

- Secret redaction is exact-match plus pattern based. In minified single-line bundles, an unrelated short secret sitting next to a match in the same snippet may stay visible. Treat reports as sensitive.
- The live HTTP client's scope check compares hostnames, not ports or schemes.
- The database live probes (`DB-L01`, `DB-L02`) are opt-in (`--probe-database`) because proving you own a website does not prove you own the Supabase/Firebase project it references. When enabled, the client may additionally make HTTPS `GET` requests to exactly `<project>.supabase.co` and `firestore.googleapis.com`, still subject to the SSRF guard and request budget. If the site's bundle points at a backend that belongs to someone else, that backend would be probed (one row per table, names only), so only use the flag on your own projects.
- Inline `whsquad-ignore RULE` comments and a `whsquad.config.json` inside the scanned repository are honoured, so a hostile repository can use them to hide its own findings. Neither happens silently: suppressed findings are counted in every report (and listed with `--show-suppressed`), and every reporter — terminal, markdown and SARIF (as a tool-execution warning) — says how many findings a policy hid, how many its baseline marked as known, whether it relaxed `failOn`, and which file it came from. When auditing code you do not trust, pass `--no-config`; the bundled GitHub Action does so by default (`use-repo-config: false`).
- A `.gitignore` in the scanned repository only affects secret severity (a git-ignored `.env` is local-only). Code agents analyse every committed source file whatever `.gitignore` says, and skip only build/vendor output.
- `whsquad fix --write`, the last-report state and the default baseline refuse to write through a symlink or junction anywhere between the project root and the target, and check every target before the first write.
- Regexes that run over whole files are kept linear: `tests/integration/hostile-input.test.ts` scans 300 KB of blank lines, open braces, nested brackets and whitespace runs with all nine agents under a time limit.
- The directory walker caps files (20,000) and file size (1 MB) but not directory count. Truncation is reported on stderr.
- `--git-history` resolves `git` from absolute `PATH` entries only, never from the scanned repository, and disables repository-local diff/pager/fsmonitor hooks.
- `whsquad review` (opt-in AI review) sends code to the user's own Claude Code CLI only after `--yes`. The model runs with every tool disabled (`--tools ""`), no MCP servers and no saved session, in a fresh per-run folder under a per-user state directory outside the scanned repo (`~/.whsquad/review` or `WHSQUAD_STATE_DIR`; Claude Code reads `CLAUDE.md` from its working folder and all parents). The review cache lives there too, so a repo cannot plant results. Only code files are sent; `.env`, key and credential files never are. Secret-shaped tokens are redacted and `.env` files are never sent. Every cited line is checked against the file before a candidate is validated, AI findings are labelled and never change the exit code, and `--max-calls` is a hard ceiling. The model can still be wrong: treat `[AI]` findings as leads to confirm, and `--recheck` results as AI-judged.
