/**
 * Tolerant, line-oriented reader for GitHub Actions workflows. It is not a YAML parser: it only
 * understands enough structure (triggers, steps, `with:`, `run:` block scalars) for four checks.
 */

export type WorkflowRule = "SUP-014" | "SUP-015" | "SUP-016" | "SUP-017";

export interface WorkflowIssue {
  readonly rule: WorkflowRule;
  readonly line: number;
  readonly snippet: string;
  readonly detail: string;
}

interface Row {
  readonly n: number;
  readonly indent: number;
  readonly text: string;
}

interface Scalar {
  /** Source rows that make up the value (inline value or block-scalar body). */
  readonly rows: readonly Row[];
}

interface Step {
  readonly rows: readonly Row[];
  readonly propIndent: number;
}

const HEAD_REF = /github\.event\.pull_request\.head\.(?:sha|ref)\b|\bgithub\.head_ref\b/;
const FORK_REPO = /github\.event\.pull_request\.head\.repo\b/;
const UNTRUSTED: readonly RegExp[] = [
  /github\.event\.issue\.(?:title|body)\b/,
  /github\.event\.pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)\b/,
  /github\.event\.(?:comment|review|review_comment)\.body\b/,
  /github\.event\.pages\[[^\]]*\]\.page_name\b/,
  /github\.event\.head_commit\.(?:message|author\.(?:email|name))\b/,
  /github\.event\.commits\[[^\]]*\]\.(?:message|author\.(?:email|name))\b/,
  /github\.event\.discussion\.(?:title|body)\b/,
  /github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.message|head_commit\.author\.(?:email|name))\b/,
  /\bgithub\.head_ref\b/,
];
const FIRST_PARTY_OWNERS: ReadonlySet<string> = new Set(["actions", "github"]);
const BRANCH_REFS = /^(?:main|master|trunk|develop|dev|HEAD)$/;

function toRows(text: string): Row[] {
  const rows: Row[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    rows.push({ n: i + 1, indent: raw.length - raw.trimStart().length, text: trimmed });
  });
  return rows;
}

function unquote(v: string): string {
  return v.trim().replace(/\s+#.*$/, "").replace(/^["']|["']$/g, "");
}

function hasPullRequestTarget(rows: readonly Row[]): boolean {
  const at = rows.findIndex((r) => r.indent === 0 && /^["']?on["']?\s*:/.test(r.text));
  if (at < 0) return false;
  const head = rows[at];
  if (head && /\bpull_request_target\b/.test(head.text)) return true;
  for (let i = at + 1; i < rows.length; i++) {
    const r = rows[i];
    if (!r || r.indent === 0) break;
    if (/^(?:-\s*)?["']?pull_request_target["']?\s*(?::|$)/.test(r.text)) return true;
  }
  return false;
}

/** Splits every `steps:` block into per-step row groups. */
function readSteps(rows: readonly Row[]): Step[] {
  const steps: Step[] = [];
  for (let i = 0; i < rows.length; i++) {
    const head = rows[i];
    if (!head || !/^steps\s*:\s*$/.test(head.text)) continue;
    let itemIndent = -1;
    let current: Row[] = [];
    const flush = (): void => {
      if (current.length > 0) steps.push({ rows: current, propIndent: itemIndent + 2 });
      current = [];
    };
    for (let j = i + 1; j < rows.length; j++) {
      const r = rows[j];
      if (!r || r.indent <= head.indent) break;
      if (itemIndent < 0 && r.text.startsWith("- ")) itemIndent = r.indent;
      if (itemIndent < 0) continue;
      if (r.indent === itemIndent && r.text.startsWith("- ")) {
        flush();
        current.push({ n: r.n, indent: itemIndent + 2, text: r.text.slice(2).trimStart() });
      } else if (current.length > 0) {
        current.push(r);
      }
    }
    flush();
  }
  return steps;
}

/** Value of `key:` among rows at exactly `indent`, handling inline values and `|` / `>` block scalars. */
function scalarOf(rows: readonly Row[], key: string, indent: number): Scalar | null {
  const re = new RegExp(`^${key}\\s*:\\s*(.*)$`);
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const m = r && r.indent === indent ? re.exec(r.text) : null;
    if (!r || !m) continue;
    const value = m[1] ?? "";
    if (!/^[|>][+-]?\d*\s*(?:#.*)?$/.test(value)) return { rows: [{ n: r.n, indent, text: value }] };
    const body: Row[] = [];
    for (let j = i + 1; j < rows.length; j++) {
      const b = rows[j];
      if (!b || b.indent <= indent) break;
      body.push(b);
    }
    return { rows: body };
  }
  return null;
}

/** Rows nested under `key:` (a mapping), with the indent of its children. */
function childrenOf(rows: readonly Row[], key: string, indent: number): { rows: readonly Row[]; indent: number } | null {
  const at = rows.findIndex((r) => r.indent === indent && new RegExp(`^${key}\\s*:\\s*$`).test(r.text));
  if (at < 0) return null;
  const kids: Row[] = [];
  for (let j = at + 1; j < rows.length; j++) {
    const r = rows[j];
    if (!r || r.indent <= indent) break;
    kids.push(r);
  }
  return kids[0] ? { rows: kids, indent: kids[0].indent } : null;
}

function checkoutIssues(step: Step): WorkflowIssue[] {
  const uses = scalarOf(step.rows, "uses", step.propIndent)?.rows[0]?.text ?? "";
  if (!/^["']?actions\/checkout(?:@|["']?$)/.test(uses)) return [];
  const withBlock = childrenOf(step.rows, "with", step.propIndent);
  if (!withBlock) return [];
  const out: WorkflowIssue[] = [];
  for (const [key, re, detail] of [
    ["ref", HEAD_REF, "checks out the pull request head"],
    ["repository", FORK_REPO, "checks out the fork's repository"],
  ] as const) {
    const row = scalarOf(withBlock.rows, key, withBlock.indent)?.rows[0];
    if (row && re.test(row.text)) out.push({ rule: "SUP-014", line: row.n, snippet: `${key}: ${unquote(row.text)}`, detail });
  }
  return out;
}

function injectionIssues(step: Step): WorkflowIssue[] {
  const scripts: Scalar[] = [];
  const run = scalarOf(step.rows, "run", step.propIndent);
  if (run) scripts.push(run);
  const uses = scalarOf(step.rows, "uses", step.propIndent)?.rows[0]?.text ?? "";
  const withBlock = /github-script/.test(uses) ? childrenOf(step.rows, "with", step.propIndent) : null;
  const script = withBlock ? scalarOf(withBlock.rows, "script", withBlock.indent) : null;
  if (script) scripts.push(script);

  const out: WorkflowIssue[] = [];
  for (const s of scripts) {
    for (const row of s.rows) {
      for (const m of row.text.matchAll(/\$\{\{([^}]*)\}\}/g)) {
        const expr = m[1] ?? "";
        if (!UNTRUSTED.some((re) => re.test(expr))) continue;
        out.push({ rule: "SUP-015", line: row.n, snippet: row.text.slice(0, 200), detail: `\${{${expr}}}` });
        break;
      }
    }
  }
  return out;
}

function pinningIssues(rows: readonly Row[]): WorkflowIssue[] {
  const out: WorkflowIssue[] = [];
  for (const r of rows) {
    const m = /^(?:-\s*)?uses\s*:\s*(.+)$/.exec(r.text);
    const ref = m ? unquote(m[1] ?? "") : "";
    if (ref === "" || ref.startsWith("./") || ref.startsWith("docker://")) continue;
    const at = ref.lastIndexOf("@");
    if (at < 0 || !BRANCH_REFS.test(ref.slice(at + 1))) continue;
    if (FIRST_PARTY_OWNERS.has(ref.split("/")[0] ?? "")) continue;
    out.push({ rule: "SUP-017", line: r.n, snippet: r.text, detail: ref });
  }
  return out;
}

export function workflowIssues(text: string): WorkflowIssue[] {
  const rows = toRows(text);
  const out: WorkflowIssue[] = [];
  const steps = readSteps(rows);

  if (hasPullRequestTarget(rows)) for (const s of steps) out.push(...checkoutIssues(s));
  for (const s of steps) out.push(...injectionIssues(s));
  for (const r of rows) {
    if (/^permissions\s*:\s*write-all\s*(?:#.*)?$/.test(r.text)) {
      out.push({ rule: "SUP-016", line: r.n, snippet: "permissions: write-all", detail: "grants every token scope" });
    }
  }
  out.push(...pinningIssues(rows));
  return out;
}

export function isWorkflowPath(path: string): boolean {
  return /^(?:.+\/)?\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
}
