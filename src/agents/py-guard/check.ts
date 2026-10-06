import { redactSecret } from "../../safety/redact.js";
import { makeFinding } from "../../core/finding.js";
import type { Confidence, Finding, Severity } from "../../core/types.js";
import type { PyFramework } from "./frameworks.js";
import { PyText } from "./pytext.js";
import { enclosing, findFunctions, taintedNames, type PyFunction } from "./scope.js";
import { RULES } from "./rules.meta.js";

export const AGENT_ID = "py-guard";
const META = new Map(RULES.map((r) => [r.id, r]));

export interface Report {
  readonly ruleId: string;
  readonly offset: number;
  readonly title?: string;
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  readonly explanation: string;
  readonly fixSummary: string;
  readonly fixCode: string;
  /** Instruction body; the file and line are prepended automatically. */
  readonly prompt: string;
  readonly references: readonly string[];
  /** Overrides the evidence snippet (used to keep secrets out of reports). */
  readonly snippet?: string;
  /** A raw secret literal on the line: redacted in the snippet and collected in `secrets`. */
  readonly secret?: string;
}

/** Per-file state shared by all rule checks. */
export class FileCheck {
  readonly pt: PyText;
  readonly funcs: readonly PyFunction[];
  readonly findings: Finding[] = [];
  readonly secrets: string[] = [];
  private readonly taintCache = new Map<PyFunction | undefined, Set<string>>();

  constructor(
    readonly path: string,
    raw: string,
    /** Frameworks imported by this file plus those declared project-wide. */
    readonly frameworks: ReadonlySet<PyFramework>,
    private readonly target: string,
  ) {
    this.pt = new PyText(raw);
    this.funcs = findFunctions(this.pt);
  }

  get code(): string {
    return this.pt.code;
  }

  fn(offset: number): PyFunction | undefined {
    return enclosing(this.funcs, offset);
  }

  tainted(fn: PyFunction | undefined): Set<string> {
    let t = this.taintCache.get(fn);
    if (!t) {
      t = taintedNames(this.pt, fn);
      this.taintCache.set(fn, t);
    }
    return t;
  }

  report(r: Report): void {
    if (this.pt.isSuppressed(r.ruleId, r.offset)) return;
    const meta = META.get(r.ruleId);
    const line = this.pt.lineOf(r.offset);
    let snippet = r.snippet ?? this.pt.snippet(r.offset);
    if (r.secret) {
      this.secrets.push(r.secret);
      snippet = snippet.split(r.secret).join(redactSecret(r.secret));
    }
    this.findings.push(
      makeFinding({
        ruleId: r.ruleId,
        agentId: AGENT_ID,
        title: r.title ?? meta?.title ?? r.ruleId,
        severity: r.severity ?? meta?.severity ?? "medium",
        confidence: r.confidence ?? "high",
        explanation: r.explanation,
        evidence: [{ file: this.path, line, snippet }],
        fix: {
          summary: r.fixSummary,
          config: r.fixCode,
          agentPrompt: `In ${this.path} at line ${line}: ${r.prompt}`,
          references: r.references,
        },
        target: this.target,
        ...(meta?.cwe ? { cwe: meta.cwe } : {}),
      }),
    );
  }
}

export const OWASP_TOP10 = "https://owasp.org/Top10/";
export const CWE = (n: number): string => `https://cwe.mitre.org/data/definitions/${n}.html`;
