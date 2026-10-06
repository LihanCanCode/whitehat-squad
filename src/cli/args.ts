import { parseArgs } from "node:util";
import { isSeverity } from "../core/severity.js";
import type { Severity } from "../core/types.js";
import { normalizePrefixes } from "../core/policy.js";
import { isReportFormat, type ReportFormat } from "../reporters/index.js";

export class UsageError extends Error {}

export interface CliOptions {
  /** `triage` is only valid for `fix`. */
  readonly format: ReportFormat | "triage";
  readonly out?: string;
  /** Resolved threshold; `failOnExplicit` says whether the user passed --fail-on (it then beats the config file). */
  readonly failOn: Severity;
  readonly failOnExplicit: boolean;
  /** Rule-id prefixes to keep / drop, upper-cased. */
  readonly only: readonly string[];
  readonly exclude: readonly string[];
  readonly baseline?: string;
  readonly maxRequests: number;
  /** `whsquad rules --agent <id>`. */
  readonly agent?: string;
  readonly showSuppressed: boolean;
  /** Ignore the scanned repo's whsquad.config.json (and the baseline it names). */
  readonly noConfig: boolean;
  readonly gitHistory: boolean;
  readonly allowPrivate: boolean;
  readonly probeDatabase: boolean;
  /** `fix --write`: apply the safe, additive changes. */
  readonly write: boolean;
  /** review: actually send code to the model (otherwise a dry run). */
  readonly yes: boolean;
  /** review: model alias or id for the Claude Code CLI. */
  readonly model: string;
  /** review: hard ceiling on model calls (hunters + validators). */
  readonly maxCalls: number;
  /** review: parallel model calls. */
  readonly concurrency: number;
  /** review: re-validate one AI finding by id. */
  readonly recheck?: string;
  readonly color: boolean | undefined;
  readonly help: boolean;
  readonly version: boolean;
}

export interface ParsedCli {
  readonly command: string | undefined;
  readonly positionals: readonly string[];
  readonly options: CliOptions;
}

const PREFIX = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]*)?$/;
const DEFAULT_MAX_REQUESTS = 100;
const MAX_REQUESTS_LIMIT = 10_000;

function parsePrefixes(flag: string, raw: string | undefined): string[] {
  const prefixes = normalizePrefixes(raw);
  const bad = prefixes.find((p) => !PREFIX.test(p));
  if (bad !== undefined) {
    throw new UsageError(`Bad ${flag} entry "${bad}". Use comma-separated rule-id prefixes such as DB or SEC-1.`);
  }
  return prefixes;
}

function parseMaxRequests(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_MAX_REQUESTS;
  const n = Number(raw);
  if (!/^\d+$/.test(raw) || n < 1 || n > MAX_REQUESTS_LIMIT) {
    throw new UsageError(`Bad --max-requests "${raw}". Use a whole number from 1 to ${MAX_REQUESTS_LIMIT}.`);
  }
  return n;
}

const MODEL = /^[A-Za-z0-9][A-Za-z0-9._\-[\]]{0,80}$/;

function parseModel(raw: string | undefined): string {
  const model = raw ?? "sonnet";
  if (!MODEL.test(model)) throw new UsageError(`Invalid --model "${model}". Use an alias such as sonnet or opus, or a model id.`);
  return model;
}

function parseBounded(flag: string, raw: string | undefined, fallback: number, min: number, max: number): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new UsageError(`${flag} must be a whole number from ${min} to ${max}.`);
  return n;
}

export function parseCli(argv: readonly string[]): ParsedCli {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        format: { type: "string", short: "f", default: "terminal" },
        out: { type: "string", short: "o" },
        "fail-on": { type: "string" },
        only: { type: "string" },
        exclude: { type: "string" },
        baseline: { type: "string" },
        "max-requests": { type: "string" },
        agent: { type: "string" },
        "show-suppressed": { type: "boolean", default: false },
        "no-config": { type: "boolean", default: false },
        "git-history": { type: "boolean", default: false },
        "allow-private": { type: "boolean", default: false },
        "probe-database": { type: "boolean", default: false },
        write: { type: "boolean", default: false },
        yes: { type: "boolean", default: false },
        model: { type: "string" },
        "max-calls": { type: "string" },
        concurrency: { type: "string" },
        recheck: { type: "string" },
        "no-color": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
    });
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }

  const { values, positionals } = parsed;
  const format = values.format ?? "terminal";
  if (!isReportFormat(format) && format !== "triage") {
    throw new UsageError(`Unknown --format "${format}". Use terminal, json, sarif, markdown, prompt or triage.`);
  }
  const failOnRaw = values["fail-on"];
  const failOn = failOnRaw ?? "high";
  if (!isSeverity(failOn)) {
    throw new UsageError(`Unknown --fail-on "${failOn}". Use critical, high, medium, low or info.`);
  }

  const [command, ...rest] = positionals;
  return {
    command,
    positionals: rest,
    options: {
      format,
      ...(values.out ? { out: values.out } : {}),
      failOn,
      failOnExplicit: failOnRaw !== undefined,
      only: parsePrefixes("--only", values.only),
      exclude: parsePrefixes("--exclude", values.exclude),
      ...(values.baseline ? { baseline: values.baseline } : {}),
      maxRequests: parseMaxRequests(values["max-requests"]),
      ...(values.agent ? { agent: values.agent } : {}),
      showSuppressed: values["show-suppressed"] ?? false,
      noConfig: values["no-config"] ?? false,
      gitHistory: values["git-history"] ?? false,
      allowPrivate: values["allow-private"] ?? false,
      probeDatabase: values["probe-database"] ?? false,
      write: values.write ?? false,
      yes: values.yes ?? false,
      model: parseModel(values.model),
      maxCalls: parseBounded("--max-calls", values["max-calls"], 30, 1, 500),
      concurrency: parseBounded("--concurrency", values.concurrency, 2, 1, 6),
      ...(values.recheck ? { recheck: values.recheck } : {}),
      color: values["no-color"] ? false : undefined,
      help: values.help ?? false,
      version: values.version ?? false,
    },
  };
}

export const HELP = `whsquad - a team of white-hat agents that audit your app and hand you the fix

Usage:
  whsquad scan <path|url> [options]     Audit a local project or a live site you own
  whsquad watch [path]                  Re-scan on every file change; print only what changed
  whsquad fix [path]                    Plan the fixes in order (dry run; --write applies safe additive changes)
  whsquad review [path]                 Opt-in AI review for logic bugs rules cannot see (dry run; --yes sends code
                                        to your Claude Code CLI). Advisory: never changes the exit code
  whsquad verify <RULE-ID> <path|url>   Re-check one rule against the last scan (same scan flags)
  whsquad baseline [path]               Record today's findings in .whsquad/baseline.json
  whsquad rules [--agent <id>]          List every rule the squad can raise
  whsquad explain <RULE-ID>             Explain one rule: what it detects, why it matters, how to fix
  whsquad init-proof <domain>           Create the ownership token for live scans
  whsquad agents                        List the squad

Options:
  -f, --format <fmt>     terminal (default), json, sarif, markdown, prompt (master fix prompt),
                         triage (fix only: validation pack); rules/explain: terminal or json
  -o, --out <file>       Write the report to a file instead of stdout
      --fail-on <sev>    Exit 1 at or above: critical, high (default), medium, low, info
      --only <prefixes>  Keep only rules whose id starts with a prefix, e.g. --only DB,SEC-1
      --exclude <prefixes>  Drop rules whose id starts with a prefix, e.g. --exclude WEB,SUP
      --baseline <file>  Findings already in this baseline are shown as known and never fail the run
      --show-suppressed  List findings hidden by whsquad-ignore comments
      --no-config        Ignore the scanned repo's whsquad.config.json (use in CI for untrusted PRs)
      --git-history      Also search git history for leaked secrets (static scans)
      --allow-private    Allow targets on private networks (RFC1918)
      --yes              review: send the planned units to the model (otherwise a dry run)
      --model <m>        review: Claude model alias or id (default sonnet)
      --max-calls <n>    review: hard ceiling on model calls (default 30)
      --concurrency <n>  review: parallel model calls (default 2)
      --recheck <id>     review: re-validate one AI finding against the current code
      --write            fix: write .gitignore lines, one new Supabase migration and .whsquad/fix-plan.md
                         (never edits existing source files)
      --probe-database   Live scans: also test whether the site's Supabase/Firestore tables are
                         publicly readable (reads at most 1 row per table, keeps names only)
      --max-requests <n> Live scans: stop after n HTTP requests (default 100)
      --agent <id>       rules: only list one agent's rules
      --no-color         Disable colors
  -h, --help             Show this help
  -v, --version          Show the version

Suppress one reviewed finding inline, in any comment syntax, on its line or the line above:
  // whsquad-ignore SEC-090 -- reason          also: DB-* wildcards, RULE,RULE lists

Project settings live in whsquad.config.json (scan root, or the current folder for live scans):
  { "failOn": "medium", "ignorePaths": ["docs/"], "rules": { "WEB-*": "low", "SUP-004": "off" },
    "baseline": ".whsquad/baseline.json" }
Command-line flags override the config file.

Live scans are read-only and only run against sites you can prove you own
(DNS TXT record or /.well-known/whsquad.txt) or against localhost.

Exit codes: 0 clean, 1 findings, 2 usage error, 3 ownership not verified, 4 internal error
`;
