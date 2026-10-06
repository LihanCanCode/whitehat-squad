import { createHash } from "node:crypto";
import { classifyFile, createSource, handlerUnits, isGeneratedPath, isTestPath, isVendorPath, lineOf, unitHas } from "../core/source/index.js";
import type { FunctionUnit, GuardName, Source } from "../core/source/index.js";
import type { FileIndex, Finding } from "../core/types.js";
import { SECRET_PATTERNS } from "../data/secret-patterns.js";
import { scrubText } from "../safety/redact.js";

/** A piece of the app small enough for one hunter call: a handler/action, or the database policies. */
export interface ReviewUnit {
  readonly id: string;
  readonly kind: "handler" | "action" | "sql";
  readonly file: string;
  readonly name: string;
  readonly method?: string;
  readonly route?: string;
  readonly startLine: number;
  readonly endLine: number;
  /** Lines of the unit not shown to the model (too long). 0 when the whole unit is shown. */
  readonly truncatedLines: number;
  /** Guards the engine found on this unit (auth, ownership, rateLimit, validation, signature). */
  readonly guards: readonly GuardName[];
  /** Line-numbered source handed to the model ("  12 | code"), secrets redacted. */
  readonly excerpt: string;
  /** One hop of local modules the unit uses, line-numbered and redacted. */
  readonly related: readonly { readonly file: string; readonly excerpt: string }[];
  /** Rule findings in the unit's files, as context ("DB-001 Table ... (file:line)"). */
  readonly ruleContext: readonly string[];
  /** Files left out of the unit (e.g. SQL over the size limit), named in the prompt and the plan. */
  readonly omitted: readonly string[];
  /** Higher = review first. */
  readonly score: number;
  /** Stable hash of everything sent for this unit (cache key input). */
  readonly contentHash: string;
}

const CODE_FILE = /\.(?:[cm]?[jt]sx?)$/i;
/** Never sent, even when imported: credentials and config that commonly hold secrets. */
const SECRET_FILE =
  /(?:^|\/)(?:\.env[^/]*|\.npmrc|\.pypirc|\.netrc|\.dev\.vars|\.git-credentials|id_[rd]sa[^/]*|[^/]*\.(?:pem|key|p12|pfx|jks|keystore|tfvars|tfstate)|[^/]*(?:credential|secret|service[-_]?account)[^/]*)$/i;
const MAX_FILE_BYTES = 400_000;
/** Import scanning is skipped beyond this (generated bundles have no useful local imports). */
const MAX_IMPORT_SCAN = 200_000;
const UNIT_WINDOW = 12;
const MAX_UNIT_LINES = 220;
const MAX_RELATED = 3;
const MAX_RELATED_LINES = 140;
const MAX_SQL_CHARS = 14_000;
const MAX_SQL_FILE_LINES = 260;
const GUARDS: readonly GuardName[] = ["auth", "ownership", "rateLimit", "validation", "signature"];
const MUTATION = /^(?:POST|PUT|PATCH|DELETE|ALL)$/;
const MONEY = /\b(?:price|amount|total|stripe|checkout|coupon|discount|credit|balance|refund|payout|plan|subscription|quantity|stock)\b/i;
const DATA = /\b(?:supabase|prisma|drizzle|db|sql|knex|mongoose|firestore|pool|client)\s*[.(]/;
const LLM = /\b(?:openai|anthropic|generateText|streamText|chat\.completions|messages\.create)\b/;
const WEBHOOK = /webhook|callback|return_url|success_url/i;

/** Line-numbered excerpt of [from, to] (1-based, inclusive). */
export function numbered(lines: readonly string[], from: number, to: number): string {
  const width = String(to).length;
  const out: string[] = [];
  for (let n = Math.max(1, from); n <= Math.min(lines.length, to); n++) out.push(`${String(n).padStart(width)} | ${(lines[n - 1] ?? "").replace(/\r$/, "")}`);
  return out.join("\n");
}

// Generic secret assignments ("JWT_SECRET = '...'", "password: \"...\"") and SQL "PASSWORD '...'".
// Bounded quantifiers only: these run over whole excerpts.
const GENERIC_SECRET = /\b((?:[\w-]{0,30}(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key)[\w-]{0,30})["']?\s{0,5}[:=]\s{0,5})(["'`])([^"'`\n]{6,300})\2/gi;
const SQL_PASSWORD = /\b(PASSWORD\s{1,5})'([^'\n]{3,300})'/gi;

/** Secret-shaped tokens, generic secret assignments and known secret values never leave the machine. */
export function redactSecrets(text: string, known: ReadonlySet<string> = new Set()): string {
  let out = scrubText(text, known);
  for (const p of SECRET_PATTERNS) {
    out = out.replace(new RegExp(p.regex.source, p.regex.flags.includes("g") ? p.regex.flags : `${p.regex.flags}g`), (m: string, g1?: unknown) =>
      typeof g1 === "string" && g1.length > 0 ? m.replace(g1, "[REDACTED]") : "[REDACTED]");
  }
  out = out.replace(GENERIC_SECRET, (_m, head: string, q: string, value: string) =>
    /^(?:process\.env|import\.meta\.env|\$\{)/.test(value) ? `${head}${q}${value}${q}` : `${head}${q}[REDACTED]${q}`);
  return out.replace(SQL_PASSWORD, (_m, head: string) => `${head}'[REDACTED]'`);
}

/** Values from .env files: known secrets to scrub from everything sent. */
export async function envSecrets(files: FileIndex): Promise<Set<string>> {
  const out = new Set<string>();
  for (const p of files.paths) {
    if (!/(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(p) || /\.example$|\.sample$|\.template$/.test(p)) continue;
    const text = (await files.read(p)) ?? "";
    for (const line of text.split(/\r?\n/).slice(0, 2000)) {
      const m = /^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]{0,100}[ \t]*=[ \t]*["']?([^"'\s#]{8,500})/.exec(line);
      if (m?.[1]) out.add(m[1]);
    }
  }
  return out;
}

// Linear: `[^"';]{0,300}` cannot backtrack quadratically on long whitespace runs.
const IMPORT = /\bimport\s[^"';]{0,300}["']([^"'\n]{1,200})["']|\bimport\(\s{0,5}["']([^"'\n]{1,200})["']|\brequire\(\s{0,5}["']([^"'\n]{1,200})["']\s{0,5}\)/g;
const EXTENSIONS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];
const JS_EXT = /\.(?:js|jsx|mjs|cjs)$/;

function dirname(p: string): string {
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}
function normalizeJoin(base: string, rel: string): string {
  const out: string[] = [];
  for (const part of `${base}/${rel}`.split("/")) {
    if (part === "..") out.pop();
    else if (part && part !== ".") out.push(part);
  }
  return out.join("/");
}
const commonPrefix = (a: string, b: string): number => {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
};

function resolveSpec(file: string, spec: string, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>): string | undefined {
  const tries = (base: string): string | undefined => {
    for (const b of JS_EXT.test(base) ? [base, base.replace(JS_EXT, "")] : [base]) {
      const hit = EXTENSIONS.map((e) => b + e).find((c) => known.has(c));
      if (hit) return hit;
    }
    return undefined;
  };
  if (spec.startsWith(".")) return tries(normalizeJoin(dirname(file), spec));
  // Path aliases (@/x, ~/x, #/x): pick the indexed file ending in that path closest to the importer
  // (handles src/, apps/web/src/ and tsconfig "paths" without parsing tsconfig).
  const alias = /^(?:@|~|#)\/(.+)$/.exec(spec);
  if (!alias?.[1]) return undefined;
  const rest = alias[1].replace(JS_EXT, "");
  const candidates = EXTENSIONS.flatMap((e) => byTail.get(`${rest}${e}`) ?? []);
  if (candidates.length === 0) return undefined;
  return [...candidates].sort((a, b) => commonPrefix(b, file) - commonPrefix(a, file) || a.length - b.length)[0];
}

function tailIndex(known: ReadonlySet<string>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const p of known) {
    const parts = p.split("/");
    for (let i = 0; i < parts.length; i++) {
      const tail = parts.slice(i).join("/");
      out.set(tail, [...(out.get(tail) ?? []), p]);
    }
  }
  return out;
}

/** Local imports of a file (relative or path-alias), resolved against the index, with the names they bind. */
export function localImports(file: string, raw: string, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]> = tailIndex(known)): { file: string; names: string[] }[] {
  if (raw.length > MAX_IMPORT_SCAN) return [];
  const found: { file: string; names: string[] }[] = [];
  for (const m of raw.matchAll(IMPORT)) {
    const spec = m[1] ?? m[2] ?? m[3] ?? "";
    const hit = resolveSpec(file, spec, known, byTail);
    if (!hit || hit === file || found.some((f) => f.file === hit)) continue;
    const clause = m[0].slice(0, m[0].lastIndexOf(spec));
    const names = [...clause.matchAll(/[A-Za-z_$][\w$]{0,60}/g)].map((n) => n[0]).filter((n) => !["import", "from", "as", "type", "require"].includes(n));
    found.push({ file: hit, names });
  }
  return found;
}

function scoreUnit(body: string, u: FunctionUnit, guards: readonly GuardName[], hasRuleFindings: boolean, file: string): number {
  let s = 0;
  if (u.action || MUTATION.test(u.httpMethod ?? "")) s += 3;
  if (DATA.test(body)) s += 2;
  if (MONEY.test(body)) s += 3;
  if (LLM.test(body)) s += 2;
  if (WEBHOOK.test(file) || WEBHOOK.test(body)) s += 2;
  if (!guards.includes("auth")) s += 2;
  if (!guards.includes("ownership") && DATA.test(body)) s += 1;
  if (hasRuleFindings) s += 1;
  return s;
}

const hash = (text: string): string => createHash("sha256").update(text).digest("hex").slice(0, 16);

function findingsIn(files: readonly string[], findings: readonly Finding[]): string[] {
  return findings
    .filter((f) => f.origin !== "ai" && f.evidence.some((e) => e.file && files.includes(e.file)))
    .slice(0, 12)
    .map((f) => {
      const e = f.evidence.find((x) => x.file && files.includes(x.file));
      return `${f.ruleId} [${f.severity}] ${f.title} (${e?.file}:${e?.line ?? "?"})`;
    });
}

interface Loaded {
  readonly path: string;
  readonly raw: string;
  readonly lines: readonly string[];
  readonly src: Source;
}

type Loader = (p: string) => Promise<Loaded | null>;

function makeLoader(files: FileIndex): Loader {
  const cache = new Map<string, Loaded | null>();
  return async (p) => {
    if (cache.has(p)) return cache.get(p) ?? null;
    const raw = SECRET_FILE.test(p) ? null : await files.read(p);
    const loaded = raw === null || raw.length > MAX_FILE_BYTES ? null : { path: p, raw, lines: raw.split("\n"), src: createSource(p, raw) };
    cache.set(p, loaded);
    return loaded;
  };
}

/** Imported modules the unit actually calls come first; only code files, never secret files. */
async function relatedFor(f: Loaded, body: string, load: Loader, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>, secrets: ReadonlySet<string>) {
  const imports = localImports(f.path, f.raw, known, byTail).filter((i) => CODE_FILE.test(i.file) && !SECRET_FILE.test(i.file));
  const used = (i: { names: string[] }): boolean => i.names.some((n) => new RegExp(`\\b${n.replace(/\$/g, "\\$")}\\b`).test(body));
  const ranked = [...imports.filter(used), ...imports.filter((i) => !used(i))];
  const related: { file: string; excerpt: string }[] = [];
  for (const imp of ranked.slice(0, MAX_RELATED)) {
    const r = await load(imp.file);
    if (!r) continue;
    const more = r.lines.length > MAX_RELATED_LINES ? `\n  ... (${r.lines.length - MAX_RELATED_LINES} more lines of this file not shown)` : "";
    related.push({ file: imp.file, excerpt: redactSecrets(numbered(r.lines, 1, MAX_RELATED_LINES), secrets) + more });
  }
  return related;
}

const TABLE_CALL = /\.from\(\s{0,5}["'`]([A-Za-z_][\w]{0,62})["'`]\s{0,5}\)/g;
const MAX_POLICY_LINES = 40;

/** SQL lines that decide access to the given tables: CREATE TABLE, ENABLE RLS, policies, grants. */
export type PolicyIndex = ReadonlyMap<string, readonly { file: string; line: number; text: string }[]>;

async function policyIndex(files: FileIndex, load: Loader): Promise<PolicyIndex> {
  const out = new Map<string, { file: string; line: number; text: string }[]>();
  for (const p of files.paths) {
    if (!/\.sql$/i.test(p) || p.includes("node_modules/")) continue;
    const f = await load(p);
    if (!f) continue;
    f.lines.forEach((text, i) => {
      if (!/\b(?:create\s+table|row\s+level\s+security|create\s+policy|alter\s+policy|drop\s+policy|grant|revoke)\b/i.test(text)) return;
      const m = /\b(?:on|table(?:\s+if\s+not\s+exists)?|alter\s+table(?:\s+only)?)\s+(?:"?public"?\.)?"?([A-Za-z_][\w]{0,62})"?/i.exec(text);
      if (!m?.[1]) return;
      const t = m[1].toLowerCase();
      out.set(t, [...(out.get(t) ?? []), { file: p, line: i + 1, text: text.replace(/\r$/, "") }]);
    });
  }
  return out;
}

/** The access rules of every Supabase table the unit's code queries, as a line-numbered excerpt. */
function policiesFor(code: string, policies: PolicyIndex, secrets: ReadonlySet<string>): { file: string; excerpt: string }[] {
  const tables = [...new Set([...code.matchAll(TABLE_CALL)].map((m) => (m[1] ?? "").toLowerCase()))];
  const lines = tables.flatMap((t) => policies.get(t) ?? []).slice(0, MAX_POLICY_LINES);
  const byFile = new Map<string, string[]>();
  for (const l of lines) byFile.set(l.file, [...(byFile.get(l.file) ?? []), `${String(l.line).padStart(4)} | ${l.text}`]);
  return [...byFile].map(([file, ls]) => ({ file, excerpt: redactSecrets(`  (access rules for ${tables.join(", ")}; other lines omitted)\n${ls.join("\n")}`, secrets) }));
}

async function handlerUnitsOf(f: Loaded, findings: readonly Finding[], load: Loader, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>, secrets: ReadonlySet<string>, policies: PolicyIndex = new Map()): Promise<ReviewUnit[]> {
  const out: ReviewUnit[] = [];
  for (const u of handlerUnits(f.src).filter((x) => x.role !== "middleware")) {
    const start = lineOf(f.src, u.start);
    const fullEnd = lineOf(f.src, u.end);
    const end = Math.min(fullEnd, start + MAX_UNIT_LINES);
    const truncatedLines = fullEnd - end;
    const body = f.raw.slice(u.start, u.end);
    const guards = GUARDS.filter((g) => unitHas(f.src, u, g, { includeRouterMiddleware: true }));
    const imported = await relatedFor(f, body, load, known, byTail, secrets);
    // Ground data access in the database: the RLS/policy lines of every table this code (or its helpers) queries.
    const related = [...imported, ...policiesFor([body, ...imported.map((r) => r.excerpt)].join("\n"), policies, secrets)];
    const header = start > 1 ? numbered(f.lines, 1, Math.min(UNIT_WINDOW, start - 1)) : "";
    const gap = start - 1 > UNIT_WINDOW ? "  ..." : "";
    const tail = truncatedLines > 0 ? `  ... (${truncatedLines} more lines of this unit not shown)` : "";
    const excerpt = redactSecrets([header, gap, numbered(f.lines, start, end), tail].filter(Boolean).join("\n"), secrets);
    const ruleContext = findingsIn([f.path, ...related.map((r) => r.file)], findings);
    const label = u.httpMethod ? `${u.httpMethod} ${u.route ?? u.name}` : u.name;
    out.push({
      id: `${f.path}#${label}`,
      kind: u.action ? "action" : "handler",
      file: f.path,
      name: label,
      ...(u.httpMethod ? { method: u.httpMethod } : {}),
      ...(u.route ? { route: u.route } : {}),
      startLine: start,
      endLine: end,
      truncatedLines,
      guards,
      excerpt,
      related,
      ruleContext,
      omitted: [],
      score: scoreUnit(body, u, guards, ruleContext.length > 0, f.path),
      contentHash: hash([excerpt, ...related.map((r) => r.excerpt), ...ruleContext].join("\n")),
    });
  }
  return out;
}

/** One unit for every database policy file, split by size; files that do not fit are named, not hidden. */
async function sqlUnit(files: FileIndex, findings: readonly Finding[], load: Loader, secrets: ReadonlySet<string>): Promise<ReviewUnit | undefined> {
  const sqlFiles = files.paths.filter((p) => /\.sql$/i.test(p) && /(?:^|\/)(?:supabase|migrations|db|database|sql)\//.test(p) && !p.includes("node_modules/")).sort();
  const parts: string[] = [];
  const omitted: string[] = [];
  let size = 0;
  for (const p of sqlFiles) {
    const f = await load(p);
    if (!f || !/\b(?:policy|row level security|grant|security definer)\b/i.test(f.raw)) continue;
    const more = f.lines.length > MAX_SQL_FILE_LINES ? `\n  ... (${f.lines.length - MAX_SQL_FILE_LINES} more lines not shown)` : "";
    const block = `-- ${p}\n${numbered(f.lines, 1, MAX_SQL_FILE_LINES)}${more}`;
    if (size + block.length > MAX_SQL_CHARS) {
      omitted.push(p);
      continue;
    }
    parts.push(block);
    size += block.length;
  }
  if (parts.length === 0) return undefined;
  const excerpt = redactSecrets(parts.join("\n\n"), secrets);
  const ruleContext = findingsIn(sqlFiles, findings);
  return {
    id: "database#policies", kind: "sql", file: sqlFiles[0] ?? "", name: "database policies", startLine: 1, endLine: 1, truncatedLines: 0,
    guards: [], excerpt, related: [], ruleContext, omitted, score: 6, contentHash: hash(excerpt + ruleContext.join("\n")),
  };
}

/** Builds review units for every JS/TS handler and Server Action, plus one unit for the SQL policies. */
export async function buildUnits(files: FileIndex, findings: readonly Finding[], secrets: ReadonlySet<string> = new Set()): Promise<ReviewUnit[]> {
  const known = new Set(files.paths);
  const byTail = tailIndex(known);
  const load = makeLoader(files);
  const policies = await policyIndex(files, load);
  const units: ReviewUnit[] = [];
  for (const p of files.paths) {
    if (!CODE_FILE.test(p) || SECRET_FILE.test(p) || isTestPath(p) || isVendorPath(p) || isGeneratedPath(p)) continue;
    const f = await load(p);
    if (!f || classifyFile(f.src) === "client") continue;
    units.push(...(await handlerUnitsOf(f, findings, load, known, byTail, secrets, policies)));
  }
  const sql = await sqlUnit(files, findings, load, secrets);
  if (sql) units.push(sql);
  // Two handlers with the same label in one file (e.g. app.post("/x") twice) keep distinct ids.
  const seen = new Map<string, number>();
  const unique = units.map((u) => {
    const n = seen.get(u.id) ?? 0;
    seen.set(u.id, n + 1);
    return n === 0 ? u : { ...u, id: `${u.id}@L${u.startLine}` };
  });
  return unique.sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : 1));
}
