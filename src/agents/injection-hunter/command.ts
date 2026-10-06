import type { Finding } from "../../core/types.js";
import type { Span } from "../../core/source/index.js";
import { splitArgs } from "../../core/source/index.js";
import { describeOrigin, flowOf, hasLiteralText } from "./flow.js";
import type { ArgFlow } from "./flow.js";
import { OWASP, bareOf, codeOf, emit, findCalls, isOneLine, parsePieces } from "./shared.js";
import type { Call, FileCtx, Piece } from "./shared.js";

const CP_IMPORT = /child_process|shelljs|execa/;
const EXEC_BARE = /(?<![\w$.])(?:exec|execSync|execAsync|execPromise|execP|asyncExec|execShell)\s*\(/;
const EXEC_MEMBER = /(?<![\w$])(?:child_process|childProcess|cp|shell|shelljs)\s*\.\s*(?:exec|execSync)\s*\(/;
const EXEC_REQUIRE = /require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*(?:exec|execSync)\s*\(/;
const SPAWN_BARE = /(?<![\w$.])(?:spawn|spawnSync|execa|execaSync)\s*\(/;
const SPAWN_MEMBER = /(?<![\w$])(?:child_process|childProcess|cp)\s*\.\s*(?:spawn|spawnSync)\s*\(/;
const SHELL_BINARY = /^(?:\/(?:usr\/)?bin\/)?(?:ba|z|da|k|c)?sh$|^cmd(?:\.exe)?$|^(?:powershell|pwsh)(?:\.exe)?$/;
const SHELL_FLAG = /^(?:-c|\/c|\/k|-Command|-lc)$/i;

function shellTrue(ctx: FileCtx, args: readonly Span[]): boolean {
  const last = args[args.length - 1];
  if (!last || !bareOf(ctx, last).startsWith("{")) return false;
  return /\bshell\s*:\s*(?!false\b|undefined\b|null\b|0\b)/.test(codeOf(ctx, last));
}

/** Split a command template into program + argument expressions for an execFile rewrite. */
function execFileRewrite(ctx: FileCtx, call: Call, tainted: ReadonlySet<number>): string | undefined {
  const arg = call.args[0];
  const name = /(exec)(Sync)?\s*\($/.exec(call.match[0]);
  if (!arg || !name || call.args.length > 2 || !isOneLine(ctx, call.index, call.close)) return undefined;
  const pieces = parsePieces(ctx.src, arg);
  if (!hasLiteralText(pieces)) return undefined;
  const tokens: Piece[][] = [];
  let cur: Piece[] = [];
  const flush = (): void => {
    if (cur.length > 0) tokens.push(cur);
    cur = [];
  };
  for (const p of pieces) {
    if (p.kind === "expr") {
      cur.push(p);
      continue;
    }
    p.text.split(/(\s+)/).forEach((part, i) => {
      if (i % 2 === 1) flush();
      else if (part !== "") cur.push({ kind: "lit", text: part, bare: "", start: p.start });
    });
  }
  flush();
  if (tokens.length === 0 || tokens[0]?.some((p) => p.kind === "expr")) return undefined;
  const render = (t: Piece[]): string => {
    if (t.every((p) => p.kind === "lit")) return JSON.stringify(t.map((p) => p.text).join(""));
    if (t.length === 1 && t[0]) return t[0].text;
    return `\`${t.map((p) => (p.kind === "lit" ? p.text : `\${${p.text}}`)).join("")}\``;
  };
  const [program, ...rest] = tokens.map(render);
  const extra = call.args.slice(1).map((a) => codeOf(ctx, a));
  const head = call.match[0].replace(/(exec)(Sync)?\s*\($/, `execFile${name[2] ?? ""}(`);
  void tainted;
  return `${head}${[program, `[${rest.join(", ")}]`, ...extra].join(", ")})`;
}

function report(ctx: FileCtx, call: Call, flow: ArgFlow, origin: string, via: string, rewrite?: string): Finding {
  const fn = call.match[0].replace(/\s*\($/, "").trim();
  return emit(ctx, {
    ruleId: "INJ-004",
    offset: call.index,
    title: "Shell command is built from request data",
    severity: "critical",
    explanation:
      `A value from ${origin} ends up in the command line run by ${fn}() (${via}). Anyone who can reach this endpoint can add shell syntax such as ; or && or $(...) ` +
      "and run their own commands on your server: read environment secrets, install a backdoor, or pivot into your network. This is full remote code execution.",
    summary: "Run a fixed program with the request values as separate arguments (no shell), and allowlist anything that selects the program.",
    ...(rewrite ? { after: rewrite } : {}),
    config:
      "import { execFile } from \"node:child_process\";\n// program and arguments are separate; there is no shell to interpret metacharacters\nexecFile(\"ping\", [\"-c\", \"1\", host], (err, stdout) => { /* ... */ });\n" +
      "// validate what the value may be before it reaches the process\nif (!/^[a-z0-9.-]{1,253}$/i.test(host)) throw new Error(\"bad host\");",
    prompt:
      `${fn}() runs a command containing ${origin}. Replace it with execFile/spawn using an argument array and no shell option, validate the value against an allowlist or strict regex, and keep the behaviour otherwise.`,
    references: [OWASP.command, "https://owasp.org/www-community/attacks/Command_Injection", "https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback"],
    cwe: "CWE-78",
  });
}

export function commandFindings(ctx: FileCtx): Finding[] {
  if (ctx.isClient) return [];
  const imported = CP_IMPORT.test(ctx.src.raw);
  const findings: Finding[] = [];

  for (const re of [EXEC_BARE, EXEC_MEMBER, EXEC_REQUIRE]) {
    if (re === EXEC_BARE && !imported) continue;
    for (const call of findCalls(ctx, re)) {
      const arg = call.args[0];
      if (!arg) continue;
      const unit = ctx.unitAt(call.open);
      const taint = ctx.taintFor(unit);
      const flow = flowOf(ctx, unit, taint, arg, call.open);
      if (flow.tainted.length === 0) continue;
      const rewrite = execFileRewrite(ctx, call, new Set(flow.tainted.map((p) => p.start)));
      findings.push(report(ctx, call, flow, describeOrigin(taint, flow.tainted, call.open), "a shell parses the whole string", rewrite));
    }
  }

  for (const re of [SPAWN_BARE, SPAWN_MEMBER]) {
    if (re === SPAWN_BARE && !imported) continue;
    for (const call of findCalls(ctx, re)) {
      const [cmd, second] = call.args;
      if (!cmd) continue;
      const unit = ctx.unitAt(call.open);
      const taint = ctx.taintFor(unit);
      const hasShell = shellTrue(ctx, call.args);
      const cmdFlow = flowOf(ctx, unit, taint, cmd, call.open);
      const elements = second && bareOf(ctx, second).startsWith("[") ? splitArgs(ctx.src, second.start + 1, second.end - 1) : [];
      const elementFlows = elements.map((e) => ({ e, flow: flowOf(ctx, unit, taint, e, call.open) }));
      const shellBinary = cmdFlow.pieces.length === 1 && cmdFlow.pieces[0]?.kind === "lit" && SHELL_BINARY.test(cmdFlow.pieces[0].text.trim());
      const dashC = elementFlows.some(({ flow }) => flow.pieces.length === 1 && flow.pieces[0]?.kind === "lit" && SHELL_FLAG.test(flow.pieces[0].text.trim()));
      let hit: ArgFlow | undefined;
      let via = "";
      if (hasShell) {
        hit = [cmdFlow, ...elementFlows.map((x) => x.flow)].find((f) => f.tainted.length > 0);
        via = "shell: true makes node pass the command and its arguments through a shell";
      } else if (shellBinary && dashC) {
        hit = elementFlows.map((x) => x.flow).find((f) => f.tainted.length > 0);
        via = "the program is a shell run with -c";
      }
      if (!hit) continue;
      findings.push(report(ctx, call, hit, describeOrigin(taint, hit.tainted, call.open), via));
    }
  }
  return findings;
}
