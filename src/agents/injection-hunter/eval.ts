import type { Finding } from "../../core/types.js";
import { describeOrigin, flowOf } from "./flow.js";
import { OWASP, emit, findCalls, isConstantPiece } from "./shared.js";
import type { Call, FileCtx, Piece } from "./shared.js";

const EVAL = /(?<![\w$.])(?:(?:window|globalThis|global|self)\s*\.\s*)?eval\s*\(/;
const NEW_FUNCTION = /(?<![\w$.])(?:new\s+)?Function\s*\(/;
const VM_RUN = /(?<![\w$.])vm\s*\.\s*(?:runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(/;
const VM_SCRIPT = /(?<![\w$.])new\s+vm\s*\.\s*Script\s*\(/;
const SCRIPT_PATH = /(?:^|\/)(?:scripts?|seeds?|migrations?|bin|tools|examples?|benchmarks?)(?:\/|\.)|\.config\.[cm]?[jt]s$/i;

/** True when a piece is neither a constant nor plain literal text. */
function isDynamic(p: Piece): boolean {
  return p.kind === "expr" && !isConstantPiece(p.bare) && !/^["'`][^"'`$]*["'`]$/.test(p.bare.trim());
}

export function evalFindings(ctx: FileCtx): Finding[] {
  const sinks: Call[] = [...findCalls(ctx, EVAL), ...findCalls(ctx, NEW_FUNCTION), ...findCalls(ctx, VM_RUN), ...findCalls(ctx, VM_SCRIPT)];
  const findings: Finding[] = [];
  const seen = new Set<number>();
  for (const call of sinks) {
    if (seen.has(call.open) || call.args.length === 0) continue;
    // `function Function(` / `class` declarations and type positions are not calls.
    if (/(?:function|class|interface|type)\s+$/.test(ctx.src.bare.slice(Math.max(0, call.index - 10), call.index + 1))) continue;
    seen.add(call.open);
    const unit = ctx.unitAt(call.open);
    const taint = ctx.taintFor(unit, true);
    const flows = call.args.map((a) => flowOf(ctx, unit, taint, a, call.open));
    const fn = call.match[0].replace(/\s*\($/, "").trim();
    const hit = flows.find((f) => f.tainted.length > 0);
    if (hit) {
      const origin = describeOrigin(taint, hit.tainted, call.open);
      findings.push(
        emit(ctx, {
          ruleId: "INJ-009",
          offset: call.index,
          title: "Request data is executed as code",
          severity: "critical",
          explanation:
            `${fn}() runs the text it is given as JavaScript, and part of that text comes from ${origin}. Anyone who can send that value can run any code inside your server process: ` +
            "read process.env secrets, query your database, read or write files, and open a reverse shell. vm modules are not a security boundary either.",
          summary: "Never execute request text. Parse it as data (JSON.parse, a schema) or map it to a fixed set of functions.",
          config:
            "// data, not code\nconst input = schema.parse(JSON.parse(body));\n// choose behaviour from a fixed table\nconst OPS = { add: (a: number, b: number) => a + b, sub: (a: number, b: number) => a - b };\nconst op = OPS[name as keyof typeof OPS];\nif (!op) throw new Error(\"unknown operation\");",
          prompt:
            `${fn}() executes a string containing ${origin}. Remove dynamic code execution: parse the input as JSON or with a small expression library, or look the operation up in a fixed object of allowed functions.`,
          references: [OWASP.injection, "https://cwe.mitre.org/data/definitions/95.html", "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!"],
          cwe: "CWE-95",
        }),
      );
      continue;
    }
    const dynamic = flows.some((f) => f.pieces.some(isDynamic));
    if (dynamic && !ctx.isClient && !SCRIPT_PATH.test(ctx.path)) {
      findings.push(
        emit(ctx, {
          ruleId: "INJ-010",
          offset: call.index,
          title: "Dynamic code execution with a non-literal string",
          severity: "medium",
          confidence: "medium",
          explanation:
            `${fn}() executes a string that is built at runtime. The scanner did not find request data reaching it, but this is the single most dangerous API in JavaScript: ` +
            "if the string ever includes user text, a plugin name, a template or a database value an attacker can edit, it becomes remote code execution on your server.",
          summary: "Replace dynamic execution with data parsing or a lookup table of allowed functions.",
          config: "const HANDLERS = { a: handlerA, b: handlerB };\nHANDLERS[key]?.(input); // instead of eval(`${key}(...)`)",
          prompt: `${fn}() executes a runtime-built string. Check where that string comes from; replace it with JSON.parse / a safe expression parser, or a lookup of allowed functions.`,
          references: [OWASP.injection, "https://cwe.mitre.org/data/definitions/95.html"],
          cwe: "CWE-95",
        }),
      );
    }
  }
  return findings;
}
