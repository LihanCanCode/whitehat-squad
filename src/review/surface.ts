import { createHash } from "node:crypto";
import { classifyFile, createSource, handlerUnits, isGeneratedPath, isTestPath, isVendorPath, lineOf, unitHas } from "../core/source/index.js";
import type { FunctionUnit, GuardName, Source } from "../core/source/index.js";
import type { FileIndex, Finding } from "../core/types.js";
import { frameworksInSource } from "../agents/py-guard/frameworks.js";
import { findFunctions, ROUTE_DECORATOR, type PyFunction } from "../agents/py-guard/scope.js";
import { PyText, statementEnd } from "../agents/py-guard/pytext.js";
import { SECRET_PATTERNS } from "../data/secret-patterns.js";
import { scrubText } from "../safety/redact.js";

/** A piece of the app small enough for one hunter call: a handler/action, or the database policies. */
export interface ReviewUnit {
  readonly id: string;
  readonly kind: "handler" | "action" | "sql";
  readonly file: string;
  readonly name: string;
  readonly framework?: "FastAPI" | "Flask" | "Django";
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
const PY_FILE = /\.py$/i;
const IMPORTABLE_FILE = /\.(?:[cm]?[jt]sx?|py)$/i;
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
const PY_FROM_IMPORT = /^[ \t]*from[ \t]+([.\w]+)[ \t]+import\b/gm;
const PY_IMPORT = /^[ \t]*import[ \t]+/gm;
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
  if (PY_FILE.test(file)) return pythonLocalImports(file, raw, known, byTail);
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

function resolvePythonModule(file: string, spec: string, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>): string | undefined {
  const dots = /^\.+/.exec(spec)?.[0].length ?? 0;
  const rest = spec.slice(dots).replace(/\./g, "/");
  const directory = dirname(file).split("/").filter(Boolean);
  const base = dots > 0
    ? [...directory.slice(0, Math.max(0, directory.length - dots + 1)), ...(rest ? rest.split("/") : [])].join("/")
    : rest;
  if (!base) return undefined;
  const endings = [`${base}.py`, `${base}/__init__.py`];
  for (const candidate of endings) if (known.has(candidate)) return candidate;
  const candidates = endings.flatMap((ending) => byTail.get(ending) ?? []);
  return candidates.sort((a, b) => commonPrefix(b, file) - commonPrefix(a, file) || a.length - b.length)[0];
}

function importedNames(clause: string): string[] {
  return clause.replace(/[()]/g, "").split(",").flatMap((part) => {
    const item = part.trim();
    if (!item || item === "*") return item === "*" ? ["*"] : [];
    const [name, alias] = item.split(/\s+as\s+/i);
    const bound = alias ?? name?.split(".")[0];
    return bound && /^[A-Za-z_]\w*$/.test(bound) ? [bound] : [];
  });
}

function pythonLocalImports(file: string, raw: string, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>): { file: string; names: string[] }[] {
  if (raw.length > MAX_IMPORT_SCAN) return [];
  const code = new PyText(raw).code;
  const found = new Map<string, Set<string>>();
  const add = (spec: string, names: readonly string[]): void => {
    const hit = resolvePythonModule(file, spec, known, byTail);
    if (!hit || hit === file) return;
    const bound = found.get(hit) ?? new Set<string>();
    for (const name of names) bound.add(name);
    found.set(hit, bound);
  };
  for (const match of code.matchAll(PY_FROM_IMPORT)) {
    const spec = match[1] ?? "";
    const clause = code.slice(match.index + match[0].length, statementEnd(code, match.index));
    const names = importedNames(clause);
    add(spec, names);
    for (const name of names) {
      if (name === "*") continue;
      if (/^\.+$/.test(spec)) add(`${spec}${name}`, [name]);
      else if (!spec.startsWith(".")) add(`${spec}.${name}`, [name]);
    }
  }
  for (const match of code.matchAll(PY_IMPORT)) {
    const clause = code.slice(match.index + match[0].length, statementEnd(code, match.index));
    for (const item of clause.split(",")) {
      const parts = item.trim().split(/\s+as\s+/i);
      const spec = parts[0]?.trim() ?? "";
      if (spec) add(spec, [parts[1]?.trim() || spec.split(".")[0] || ""]);
    }
  }
  return [...found].map(([path, names]) => ({ file: path, names: [...names] }));
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
  const imports = localImports(f.path, f.raw, known, byTail).filter((i) => IMPORTABLE_FILE.test(i.file) && !SECRET_FILE.test(i.file));
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

interface PythonRoute {
  readonly framework: "FastAPI" | "Flask" | "Django";
  readonly method?: string;
  readonly path?: string;
}

function pythonDecorators(pt: PyText, fn: PyFunction): { code: string; raw: string }[] {
  const found: { code: string; raw: string }[] = [];
  const code = pt.code.slice(fn.start, fn.defStart);
  for (const match of code.matchAll(/^[ \t]*@/gm)) {
    const start = fn.start + match.index + match[0].lastIndexOf("@");
    const end = statementEnd(pt.code, start);
    found.push({ code: pt.code.slice(start, end).trim(), raw: pt.raw.slice(start, end).trim() });
  }
  return found;
}

function pythonRoute(fn: PyFunction, decorators: readonly { code: string; raw: string }[], frameworks: ReadonlySet<string>): PythonRoute | undefined {
  const routeDecorator = decorators.find(({ code }) => ROUTE_DECORATOR.test(code));
  if (!routeDecorator) return undefined;
  const djangoDecorator = /^@\s*(?:api_view|action)\b/.test(routeDecorator.code);
  let framework: PythonRoute["framework"];
  if (djangoDecorator && frameworks.has("django")) framework = "Django";
  else if (frameworks.has("fastapi")) framework = "FastAPI";
  else if (frameworks.has("flask")) framework = "Flask";
  else return undefined;

  const decoratorName = /^@\s*(?:[\w]+\s*\.\s*)*([\w]+)\s*\(/.exec(routeDecorator.code)?.[1]?.toLowerCase();
  const raw = routeDecorator.raw;
  const firstString = /["']([^"'\n]*)["']/.exec(raw)?.[1];
  const listedMethods = /\bmethods\s*=\s*\[([^\]]{0,200})\]/i.exec(raw)?.[1];
  const apiMethods = framework === "Django" ? /@\s*api_view\s*\(\s*\[([^\]]{0,200})\]/i.exec(raw)?.[1] : undefined;
  const methods = (listedMethods ?? apiMethods)?.match(/["']([A-Za-z]+)["']/g)?.map((m) => m.slice(1, -1).toUpperCase());
  const method = methods?.length
    ? [...new Set(methods)].join(", ")
    : decoratorName && ["get", "post", "put", "patch", "delete", "head", "options"].includes(decoratorName)
      ? decoratorName.toUpperCase()
      : framework === "Flask" && decoratorName === "route"
        ? "GET"
        : undefined;
  return { framework, ...(method ? { method } : {}), ...(firstString && !djangoDecorator ? { path: firstString } : {}) };
}

async function pythonRouteUnitsOf(f: Loaded, findings: readonly Finding[], load: Loader, known: ReadonlySet<string>, byTail: ReadonlyMap<string, readonly string[]>, secrets: ReadonlySet<string>): Promise<ReviewUnit[]> {
  const pt = new PyText(f.raw);
  const funcs = findFunctions(pt);
  const frameworks = frameworksInSource(f.raw);
  const seenRoutes = new Set<string>();
  const out: ReviewUnit[] = [];
  for (const fn of funcs) {
    const route = pythonRoute(fn, pythonDecorators(pt, fn), frameworks);
    if (!route) continue;
    const routeLabel = route.method ? `${route.method} ${route.path ?? fn.name}` : route.path ?? fn.name;
    const routeKey = `${route.method ?? ""}\n${route.path ?? fn.name}`;
    if (seenRoutes.has(routeKey)) continue;
    seenRoutes.add(routeKey);

    const start = pt.lineOf(fn.start);
    const fullEnd = pt.lineOf(Math.max(fn.start, fn.bodyEnd - 1));
    const end = Math.min(fullEnd, start + MAX_UNIT_LINES - 1);
    const truncatedLines = fullEnd - end;
    const body = f.raw.slice(fn.start, fn.bodyEnd);
    const imported = await relatedFor(f, body, load, known, byTail, secrets);
    const excerpt = redactSecrets(`${numbered(f.lines, start, end)}${truncatedLines > 0 ? `\n  ... (${truncatedLines} more lines of this unit not shown)` : ""}`, secrets);
    const ruleContext = findingsIn([f.path, ...imported.map((r) => r.file)], findings);
    const guards: readonly GuardName[] = [];
    let score = route.method?.split(/,\s*/).some((method) => MUTATION.test(method)) ? 3 : 0;
    if (DATA.test(body)) score += 2;
    if (MONEY.test(body)) score += 3;
    if (LLM.test(body)) score += 2;
    if (WEBHOOK.test(route.path ?? "") || WEBHOOK.test(body)) score += 2;
    score += 2;
    if (ruleContext.length > 0) score += 1;
    out.push({
      id: `${f.path}#${routeLabel}`,
      kind: "handler",
      file: f.path,
      name: routeLabel,
      framework: route.framework,
      ...(route.method ? { method: route.method } : {}),
      ...(route.path ? { route: route.path } : {}),
      startLine: start,
      endLine: end,
      truncatedLines,
      guards,
      excerpt,
      related: imported,
      ruleContext,
      omitted: [],
      score,
      contentHash: hash([excerpt, ...imported.map((r) => r.excerpt), ...ruleContext].join("\n")),
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
    if (SECRET_FILE.test(p) || isTestPath(p) || isVendorPath(p) || isGeneratedPath(p)) continue;
    if (PY_FILE.test(p)) {
      const f = await load(p);
      if (f) units.push(...(await pythonRouteUnitsOf(f, findings, load, known, byTail, secrets)));
      continue;
    }
    if (!CODE_FILE.test(p)) continue;
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
