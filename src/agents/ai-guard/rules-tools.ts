import { analyzeTaint, matchClose, parseParams, splitArgs, unitHas } from "../../core/source/index.js";
import type { FunctionUnit } from "../../core/source/index.js";
import { readFunctionAt } from "../../core/source/functions.js";
import { skipTemplate } from "../../core/source/scan.js";
import { bareMatches, codeMatches, handlerAt, scopeAt } from "./context.js";
import type { Ctx, Hit } from "./context.js";

// ---------------------------------------------------------------------------------------------
// AI-008: MCP tool handlers that pass model-controlled arguments to dangerous sinks

const MCP_FILE = /@modelcontextprotocol|mcp-handler|@vercel\/mcp-adapter|\bfastmcp\b|\bMcpServer\b|\bCallToolRequestSchema\b|mcp-use|@mastra\/mcp/i;
const TOOL_REGISTRATION =
  /\b[A-Za-z_$][\w$]*\s*\.\s*(?:tool|registerTool|addTool)\s*\(|\bsetRequestHandler\s*\(\s*CallToolRequestSchema\s*,/g;
const ALLOWLIST =
  /\b(?:allow\w*|ALLOW\w*|whitelist\w*|safeJoin|isPathInside|isSubPath|realpath\w*)\b|\.startsWith\s*\(|\bpath\s*\.\s*relative\s*\(|\bnew\s+URL\s*\([^)]*\)\s*\.\s*(?:hostname|host|origin)/;

interface SinkDef {
  readonly kind: "exec" | "fetch" | "fs" | "sql";
  readonly re: RegExp;
  readonly severity: "critical" | "high";
  readonly shell?: boolean;
}

const SINK_DEFS: readonly SinkDef[] = [
  { kind: "exec", re: /(?<![.\w$])(?:exec|execSync)\s*\(|\b(?:child_process|cp|childProcess)\s*\.\s*(?:exec|execSync)\s*\(/g, severity: "critical" },
  { kind: "exec", re: /(?<![.\w$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(|\b(?:child_process|cp|childProcess)\s*\.\s*(?:spawn|spawnSync|execFile|execFileSync)\s*\(/g, severity: "high" },
  { kind: "fetch", re: /(?<![.\w$])fetch\s*\(|\baxios\s*(?:\.\s*(?:get|post|put|request)\s*)?\(|\bgot\s*\(/g, severity: "high" },
  {
    kind: "fs",
    re: /\b(?:fs|fsp|fsPromises|promises)\s*(?:\.\s*promises\s*)?\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream|createWriteStream|readdir|unlink|rm|rmSync)\s*\(|(?<![.\w$])(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(/g,
    severity: "high",
  },
  { kind: "sql", re: /\.\s*(?:query|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(|(?<!\bString)\.raw\s*\(/g, severity: "high" },
];

/** The function a tool registration hands to the SDK: an inline callback, or a named function. */
function handlerOfRegistration(c: Ctx, open: number, close: number): FunctionUnit | undefined {
  const args = splitArgs(c.src, open + 1, close - 1);
  for (let k = args.length - 1; k >= 0; k--) {
    const a = args[k];
    if (!a) continue;
    const init = readFunctionAt(c.src, a.start);
    if (init) return { name: "<tool>", kind: init.kind, exported: false, start: a.start, end: init.end, bodyStart: init.bodyStart, params: init.params };
  }
  const tail = args[args.length - 1];
  const name = tail ? c.src.bare.slice(tail.start, tail.end).trim() : "";
  return /^[A-Za-z_$][\w$]*$/.test(name) ? c.units.find((u) => u.name === name) : undefined;
}

function taintedParamNames(unit: FunctionUnit): string[] {
  return parseParams(unit.params).flatMap((p) => p.names);
}

/** AI-008: tool arguments chosen by a model reach exec / spawn / fetch / fs / SQL with no allowlist. */
export function detectMcpToolSinks(c: Ctx): Hit[] {
  if (c.isClient || !MCP_FILE.test(c.src.code)) return [];
  const hits: Hit[] = [];
  const seen = new Set<number>();
  for (const reg of bareMatches(c.src, TOOL_REGISTRATION)) {
    const open = reg.index + reg[0].indexOf("(");
    const close = matchClose(c.src, open);
    if (close < 0) continue;
    const unit = handlerOfRegistration(c, open, close);
    if (!unit) continue;
    const taint = analyzeTaint(c.src, unit, { taintedNames: taintedParamNames(unit), seedParams: false });
    const body = c.src.bare.slice(unit.start, unit.end);
    const guarded = ALLOWLIST.test(body);
    const schemaEnum = /\.\s*(?:enum|literal)\s*\(/.test(c.src.code.slice(open, unit.start));
    for (const sink of SINK_DEFS) {
      for (const m of bareMatches(c.src, sink.re)) {
        if (m.index < unit.start || m.index >= unit.end || seen.has(m.index)) continue;
        const sOpen = m.index + m[0].length - 1;
        const sClose = matchClose(c.src, sOpen);
        if (sClose < 0) continue;
        const args = splitArgs(c.src, sOpen + 1, sClose - 1);
        const watched = sink.kind === "sql" || sink.kind === "fetch" ? args.slice(0, 1) : args;
        if (!watched.some((a) => taint.isTainted(c.src.code.slice(a.start, a.end), m.index))) continue;
        if (guarded) continue;
        seen.add(m.index);
        hits.push({
          ruleId: "AI-008",
          index: m.index,
          severity: sink.severity,
          confidence: schemaEnum ? "low" : "high",
          variant: sink.kind,
        });
      }
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------------------------
// AI-009: RAG / vector queries without a tenant filter

const TENANT = /\b\w*(?:user|tenant|org|owner|account|workspace|team|customer|company)\w*\b/i;
const VECTOR_OP = /<=>|<->|<#>/;
const NL = String.fromCharCode(10);

/** The template literal containing `at` (the whole SQL text), else the surrounding three lines. */
function windowAround(c: Ctx, at: number): string {
  const b = c.src.bare;
  for (let i = b.lastIndexOf("`", at); i >= 0; i = b.lastIndexOf("`", i - 1)) {
    const end = skipTemplate(c.src, i);
    if (end > at) return c.src.code.slice(i, end);
    if (i === 0) break;
  }
  const code = c.src.code;
  const from = code.lastIndexOf(NL, code.lastIndexOf(NL, at - 1) - 1);
  const next = code.indexOf(NL, at);
  const to = next < 0 ? -1 : code.indexOf(NL, next + 1);
  return code.slice(Math.max(0, from), to < 0 ? undefined : to);
}

interface RagContext {
  readonly perUser: boolean;
}

function ragContext(c: Ctx, at: number): RagContext {
  const handler = handlerAt(c, at);
  return { perUser: c.env.hasUserAuth || (handler ? unitHas(c.src, handler, "auth") : unitHas(c.src, scopeAt(c, at), "auth")) };
}

function pineconeQueries(c: Ctx): number[] {
  const out: number[] = [];
  for (const m of bareMatches(c.src, /\b(?:index|idx|pc|pinecone|ns|namespace|vectorIndex|pineconeIndex)\w*(?:\s*\.\s*(?:namespace|ns)\s*\([^)]*\))?\s*\.\s*query\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(c.src, open);
    if (close < 0) continue;
    const args = c.src.bare.slice(open + 1, close - 1);
    const callText = c.src.bare.slice(m.index, close);
    if (!/\btopK\b|\bvector\b|\bid\s*:/.test(args)) continue;
    if (/\bfilter\b|\bnamespace\b|\.\s*ns\s*\(/.test(callText)) continue;
    out.push(m.index);
  }
  return out;
}

function supabaseRpcQueries(c: Ctx): number[] {
  const out: number[] = [];
  for (const m of codeMatches(c.src, /\.\s*rpc\s*\(\s*["'`](match_\w+|\w*match_documents\w*|\w*vector_search\w*)["'`]/)) {
    const open = c.src.code.indexOf("(", m.index);
    const close = matchClose(c.src, open);
    if (close < 0) continue;
    const args = splitArgs(c.src, open + 1, close - 1);
    const params = args[1] ? c.src.code.slice(args[1].start, args[1].end) : "";
    if (TENANT.test(params) || /\bfilter\b/.test(params)) continue;
    out.push(m.index);
  }
  return out;
}

function pgvectorQueries(c: Ctx): number[] {
  const out: number[] = [];
  const seenLines = new Set<number>();
  for (const m of c.src.code.matchAll(new RegExp(VECTOR_OP.source, "g"))) {
    if (c.src.bare.charAt(m.index) === c.src.code.charAt(m.index)) continue; // an operator in code, not in SQL text
    const sql = windowAround(c, m.index);
    if (!/\bselect\b/i.test(sql) || !/\border\s+by\b/i.test(sql)) continue;
    if (TENANT.test(sql)) continue;
    const line = c.src.code.slice(0, m.index).split("\n").length;
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    out.push(m.index);
  }
  return out;
}

/** AI-009: similarity search over a shared index with no per-user / per-tenant scope in an app with user auth. */
export function detectUnscopedVectorQuery(c: Ctx): Hit[] {
  if (c.isClient) return [];
  const found: Array<[number, string]> = [
    ...pineconeQueries(c).map((i): [number, string] => [i, "pinecone"]),
    ...supabaseRpcQueries(c).map((i): [number, string] => [i, "supabase"]),
    ...pgvectorQueries(c).map((i): [number, string] => [i, "pgvector"]),
  ];
  return found
    .filter(([at]) => ragContext(c, at).perUser)
    .map(([index, variant]) => ({ ruleId: "AI-009" as const, index, severity: "medium" as const, confidence: "low" as const, variant }));
}
