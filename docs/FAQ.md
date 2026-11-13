# FAQ

### Does `whsquad` send my code anywhere?
No. Rule-based scanning runs fully offline. Only the opt-in AI review ([AI-REVIEW.md](AI-REVIEW.md))
talks to an LLM, and only when you turn it on.

### How is this different from a pentest tool?
Agentic pentest tools target security professionals and usually need Docker plus an API key.
`whsquad` is the fast, free hygiene check you run right after your coding agent writes code.
Still get a real penetration test before a serious launch.

### My CI fails, but I only want to block on new problems.
Record today's findings with `whsquad baseline .` and point `"baseline"` in `whsquad.config.json`
at the file. Later runs fail only on findings that aren't in the baseline.

### The scanner flagged something that is safe. What now?
Add `// whsquad-ignore <RULE-ID>` on the line, but only after you have actually checked it.
Suppressions are listed with `--show-suppressed`, and please
[report the false positive](https://github.com/LihanCanCode/whitehat-squad/issues/new/choose).

### Can a cloned repo silence the scanner with its own config?
Every report warns when a repo's `whsquad.config.json` hides findings. When auditing code you don't
trust, pass `--no-config` to ignore it completely.

### What do the exit codes mean?
`0` clean · `1` findings at or above `--fail-on` (default `high`) · `2` usage error ·
`3` live-scan ownership not verified · `4` internal error.

### Can I scan a website I don't own?
No. Live scans require proof of ownership (a DNS TXT record or `/.well-known/whsquad.txt`).
See [SECURITY.md](../SECURITY.md).
