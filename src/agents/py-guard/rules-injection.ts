import { CWE, OWASP_TOP10, type FileCheck } from "./check.js";
import { isDynamicString, withoutLiterals } from "./pytext.js";
import { findAssignment, usesRequestData } from "./scope.js";
import { argText, callsMatching, type Call } from "./util.js";

const IDENT_ONLY = /^\s*([A-Za-z_]\w*)\s*$/;

interface ArgRange {
  readonly start: number;
  readonly end: number;
}

/** Resolves a bare-identifier argument to the expression it was last assigned (same function). */
export function resolve(fc: FileCheck, arg: ArgRange): ArgRange {
  const m = IDENT_ONLY.exec(fc.code.slice(arg.start, arg.end));
  if (!m) return arg;
  const assigned = findAssignment(fc.pt, fc.fn(arg.start), m[1] as string, arg.start);
  return assigned ?? arg;
}

interface Verdict {
  readonly dynamic: boolean;
  readonly tainted: boolean;
}

export function judge(fc: FileCheck, arg: ArgRange, offset: number): Verdict {
  const target = resolve(fc, arg);
  const dynamic = isDynamicString(fc.pt, target.start, target.end);
  const tainted = fc.tainted(fc.fn(offset));
  const text = fc.code.slice(arg.start, arg.end) + " " + fc.code.slice(target.start, target.end);
  return { dynamic, tainted: usesRequestData(text, tainted) };
}

const SQL_DOCS = "https://docs.sqlalchemy.org/en/20/core/tutorial.html#using-textual-sql";
const SQL_FIX_SUMMARY = "Pass values as bound parameters; never format them into the SQL text.";

function sqlReport(fc: FileCheck, call: Call, tainted: boolean): void {
  fc.report({
    ruleId: "PY-006", offset: call.index, severity: tainted ? "critical" : "high",
    explanation:
      "This SQL statement is built by pasting values into the query text. An attacker who controls any of those values " +
      (tainted ? "(here they come straight from the HTTP request) " : "") +
      "can add their own SQL: dump every user's data and password hashes, bypass login with ' OR 1=1 --, or drop tables.",
    fixSummary: SQL_FIX_SUMMARY,
    fixCode:
      '# DB-API (psycopg2/sqlite3/mysql)\ncursor.execute("SELECT * FROM users WHERE email = %s", (email,))\n\n' +
      '# SQLAlchemy\nsession.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})\n\n' +
      '# Django ORM / raw\nUser.objects.raw("SELECT * FROM app_user WHERE email = %s", [email])',
    prompt: "This query interpolates values into the SQL string. Rewrite it with bound parameters (%s with a tuple, :name with a dict, or the ORM) so no value is ever formatted into the SQL text.",
    references: [SQL_DOCS, CWE(89), OWASP_TOP10],
  });
}

/** PY-006: SQL injection through string-built statements. */
export function sqlInjection(fc: FileCheck): void {
  const sqlalchemy = /\bsqlalchemy\b/.test(fc.pt.raw);
  const django = /\bdjango\b|\.objects\b/.test(fc.pt.raw);
  const patterns: RegExp[] = [/\.(?:execute|executemany|executescript|exec_driver_sql)\s*\(/];
  if (sqlalchemy) patterns.push(/(?<![.\w])text\s*\(/);
  if (django) patterns.push(/\.raw\s*\(/, /\.extra\s*\(/);
  const seen = new Set<number>();
  for (const re of patterns) {
    for (const call of callsMatching(fc, re)) {
      const first = call.args[0];
      if (!first || seen.has(call.index)) continue;
      const isExtra = /extra\s*\($/.test(fc.code.slice(call.index, call.open + 1));
      if (/^\s*text\s*\(/.test(fc.code.slice(first.start, first.end))) continue; // reported by the text() call
      const range = isExtra ? { start: call.open + 1, end: call.end - 1 } : first;
      const verdict = judge(fc, range, call.index);
      if (!verdict.dynamic) continue;
      seen.add(call.index);
      sqlReport(fc, call, verdict.tainted);
    }
  }
}

const SUBPROCESS = /\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(/;
const OS_SHELL = /\bos\s*\.\s*(?:system|popen)\s*\(|\bcreate_subprocess_shell\s*\(/;
const CMD_DOCS = "https://docs.python.org/3/library/subprocess.html#security-considerations";

function cmdReport(fc: FileCheck, offset: number, tainted: boolean, confidence: "high" | "medium"): void {
  fc.report({
    ruleId: "PY-007", offset, severity: tainted ? "critical" : "high", confidence,
    explanation:
      "A shell command is assembled from variable data and executed by a shell. Shell metacharacters in that data " +
      "(; | && $(...) backticks) let an attacker run any command as your server user: read secrets, install malware, " +
      "pivot into your network." + (tainted ? " The data comes straight from the HTTP request, so this is exploitable by anyone." : ""),
    fixSummary: "Pass an argument list without shell=True, and validate the value against an allowlist.",
    fixCode:
      'import subprocess\n\nsubprocess.run(["convert", input_path, output_path], check=True, timeout=30)  # no shell\n# validate first: if name not in ALLOWED_NAMES: abort(400)',
    prompt: "This command is built from non-literal data and run through a shell. Switch to subprocess.run([...list of args...], check=True) without shell=True and validate user-supplied values against an allowlist.",
    references: [CMD_DOCS, CWE(78), OWASP_TOP10],
  });
}

/** PY-007: OS command injection. */
export function commandInjection(fc: FileCheck): void {
  for (const call of callsMatching(fc, SUBPROCESS)) {
    const first = call.args[0];
    if (!first || !/\bshell\s*=\s*True\b/.test(argText(fc, call))) continue;
    const verdict = judge(fc, first, call.index);
    if (verdict.dynamic || verdict.tainted) cmdReport(fc, call.index, verdict.tainted, "high");
  }
  for (const call of callsMatching(fc, OS_SHELL)) {
    const first = call.args[0];
    if (!first) continue;
    const verdict = judge(fc, first, call.index);
    const target = resolve(fc, first);
    const nonLiteral = /[A-Za-z_]/.test(withoutLiterals(fc.pt, target.start, target.end));
    if (verdict.dynamic || verdict.tainted) cmdReport(fc, call.index, verdict.tainted, "high");
    else if (nonLiteral) cmdReport(fc, call.index, false, "medium");
  }
}

const EVAL_CALL = /(?<![.\w])(?:eval|exec)\s*\(/;

/** PY-009: eval/exec on non-literal strings. */
export function evalExec(fc: FileCheck): void {
  for (const call of callsMatching(fc, EVAL_CALL)) {
    const first = call.args[0];
    if (!first) continue;
    if (withoutLiterals(fc.pt, first.start, first.end).trim() === "") continue; // literal only
    const tainted = usesRequestData(fc.code.slice(first.start, first.end), fc.tainted(fc.fn(call.index)))
      || judge(fc, first, call.index).tainted;
    fc.report({
      ruleId: "PY-009", offset: call.index, severity: tainted ? "critical" : "medium",
      explanation: tainted
        ? "eval()/exec() runs text taken from the HTTP request as Python code. Anyone can send code that reads your " +
          "environment variables, files and database, or opens a reverse shell: full server takeover."
        : "eval()/exec() runs a string built at runtime. Today the string may be safe, but one future change that lets user " +
          "input reach it turns this into full server takeover, and it hides logic from review and static analysis.",
      fixSummary: "Parse data with ast.literal_eval / json.loads, and dispatch operations through an explicit allowlist.",
      fixCode:
        'import ast, json\n\nvalue = ast.literal_eval(text)      # literals only\ndata = json.loads(text)           # JSON\nOPS = {"add": operator.add}\nresult = OPS[name](a, b)           # explicit allowlist',
      prompt: "Replace this eval/exec with ast.literal_eval, json.loads or an explicit dispatch dictionary so no input is ever executed as code.",
      references: ["https://docs.python.org/3/library/ast.html#ast.literal_eval", CWE(95), OWASP_TOP10],
    });
  }
}
