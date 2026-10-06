import type { Finding, ScanReport } from "../core/types.js";
import { ruleMeta } from "../rules/catalog.js";
import { SECRET_PATTERNS } from "../data/secret-patterns.js";
import { redactSecret } from "../safety/redact.js";
import { stripControl } from "../reporters/util.js";
import { compareFindings } from "./phases.js";
import { DATA_BOUNDARY } from "./prompts.js";

/** Lines of context shown above and below the evidence line. */
export const WINDOW_RADIUS = 8;
const MAX_LINE_CHARS = 240;
const ENV_FILE = /(?:^|\/)\.env(?:\.[A-Za-z0-9_-]+)?$/;
const KEYISH_LINE = /key|secret|token|passw|pwd|credential/i;
const LONG_TOKEN = /[A-Za-z0-9+/=_.-]{24,}/g;

export type ReadFile = (relPath: string) => Promise<string | null>;

/** Questions that try to disprove a finding, by rule prefix. Always exactly three. */
export function questionsFor(ruleId: string): readonly [string, string, string] {
  if (ruleId.startsWith("AUTH-") || /^PY-(?:004|005|012|013|014)$/.test(ruleId)) {
    return [
      "Is there an auth check in a middleware, wrapper or helper this handler goes through? Quote it.",
      "Does the framework, gateway or route config enforce authentication before this code runs (for example a matcher, a router guard or a decorator on the router)?",
      "Does this route actually touch user data or a privileged action, or is it intentionally public?",
    ];
  }
  if (ruleId.startsWith("DB-")) {
    return [
      "Is there a later migration that changes this (a newer policy, a DROP, an ALTER or a REVOKE)? Quote it.",
      "Is access restricted somewhere this scan cannot see, such as the Supabase dashboard, a view, or a role that anon/authenticated never reaches?",
      "Does the table or function really hold user or sensitive data, or is it intentionally public reference data?",
    ];
  }
  if (ruleId.startsWith("INJ-") || /^PY-(?:006|007|008|009|010|011)$/.test(ruleId) || ruleId === "AI-003") {
    return [
      "Can the value actually be attacker-controlled here? Trace it back to its source and quote each step.",
      "Is it validated, escaped, parameterized or allow-listed on the way to this sink? Quote the code that does it.",
      "Is this code reachable in production, or is it a test, script or dead path?",
    ];
  }
  if (ruleId.startsWith("SEC-") || ruleId === "PY-003") {
    return [
      "Is this a real credential, or a placeholder, test fixture, documentation example or public/publishable key?",
      "Is the value live (for example check the prefix and provider docs), or already revoked? Never print or paste the value.",
      "Is the file actually shipped or committed, or is it local-only and git-ignored?",
    ];
  }
  if (ruleId.startsWith("SUP-")) {
    return [
      "Is the vulnerable version really the one installed (check the lockfile), or is it overridden or deduped to a patched version?",
      "Is the vulnerable code path reachable in how this project uses the package, or is it a dev-only dependency?",
      "Is there a newer release that fixes it and is compatible with this project's other dependencies?",
    ];
  }
  return [
    "Is there a mitigation elsewhere (middleware, config, infrastructure, another layer) that this scan cannot see? Quote it.",
    "Does the code at the cited lines really do what the finding claims? Quote the relevant lines.",
    "Is this code reachable and used in production, or is it a test, example or dead code?",
  ];
}

function redactLine(line: string): string {
  let out = line;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(new RegExp(p.regex.source, p.regex.flags.replace("d", "")), (m, g1: unknown) => {
      const secret = typeof g1 === "string" && g1.length > 0 ? g1 : m;
      return m.replace(secret, redactSecret(secret));
    });
  }
  if (KEYISH_LINE.test(out)) out = out.replace(LONG_TOKEN, (t) => redactSecret(t));
  return out.length > MAX_LINE_CHARS ? `${out.slice(0, MAX_LINE_CHARS)}...` : out;
}

/** Numbered lines around `line` (1-based), with ">" on the evidence line. Secrets are masked. */
export function codeWindow(text: string, line: number, radius = WINDOW_RADIUS): string {
  const lines = stripControl(text).split("\n");
  const from = Math.max(1, line - radius);
  const to = Math.min(lines.length, line + radius);
  const width = String(to).length;
  const out: string[] = [];
  for (let n = from; n <= to; n++) {
    out.push(`${n === line ? ">" : " "} ${String(n).padStart(width)} | ${redactLine(lines[n - 1] ?? "")}`);
  }
  return out.join("\n");
}

async function windowsFor(f: Finding, read: ReadFile): Promise<string[]> {
  const blocks: string[] = [];
  const shown = new Set<string>();
  for (const ev of f.evidence) {
    if (!ev.file || !ev.line) continue;
    const key = oneLine(`${ev.file}:${ev.line}`);
    if (shown.has(key)) continue;
    shown.add(key);
    if (f.ruleId.startsWith("SEC-") || ENV_FILE.test(ev.file)) {
      blocks.push(`${key}: (code window withheld: this location holds credentials; use the redacted evidence above)`);
      continue;
    }
    const text = await read(ev.file);
    blocks.push(text === null ? `${key}: (file could not be read)` : `${key}\n\`\`\`\n${codeWindow(text, ev.line)}\n\`\`\``);
  }
  return blocks;
}

const oneLine = (s: string): string => stripControl(s).replace(/\s+/g, " ").trim();

async function findingBlock(f: Finding, read: ReadFile, n: number): Promise<string> {
  const meta = ruleMeta(f.ruleId);
  const lines = [
    `## Finding ${n}: ${oneLine(f.title)} (${f.ruleId}, id ${f.id})`,
    `Severity: ${f.severity} | Confidence: ${f.confidence}${f.baseline ? " | known (baseline)" : ""}`,
    "",
    `Rule: ${meta ? oneLine(meta.title) : oneLine(f.ruleId)}`,
    ...(meta ? [`What the rule says: ${oneLine(meta.summary)}`] : []),
    "",
    "Why it was raised:",
    oneLine(f.explanation),
    "",
    "Evidence:",
    ...f.evidence.map((e) => `- ${oneLine(e.file ? `${e.file}${e.line ? `:${e.line}` : ""}` : (e.url ?? ""))}: ${oneLine(e.snippet)}`),
    "",
    ...(await windowsFor(f, read)).flatMap((w) => [w, ""]),
    "Try to disprove it:",
    ...questionsFor(f.ruleId).map((q, i) => `${i + 1}. ${q}`),
    "",
  ];
  return lines.join("\n");
}

/** The validation pack: every low/medium-confidence finding with a code window and adversarial questions. */
export async function renderTriagePack(report: ScanReport, read: ReadFile): Promise<string> {
  const candidates = report.findings.filter((f) => f.confidence !== "high").sort(compareFindings);
  const head = [
    "# whitehat-squad triage pack",
    "",
    `Target: ${oneLine(report.target)}`,
    "",
    "These findings were raised with low or medium confidence. Your job is to try to DISPROVE each one by reading the code, not to fix it.",
    "",
    DATA_BOUNDARY,
    "",
  ];
  if (candidates.length === 0) return [...head, "No low or medium confidence findings: nothing to triage.", ""].join("\n");
  const blocks: string[] = [];
  for (const [i, f] of candidates.entries()) blocks.push(await findingBlock(f, read, i + 1));
  const tail = [
    "## Your answer",
    "",
    "For EVERY finding above, answer with exactly one of:",
    "- CONFIRMED: it is a real problem (say why, quoting the code)",
    "- REJECTED: it is a false positive (give the reason, quoting the code or config that disproves it)",
    "- NEEDS-HUMAN: you cannot tell from the code (say what the user must check)",
    "",
    "Do NOT modify any code, config, migration or file during triage. Only read and answer. Fixing happens afterwards, from `whsquad fix`, and only for CONFIRMED findings.",
    "",
  ];
  return [...head, ...blocks, ...tail].join("\n");
}
