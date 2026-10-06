import { ID, QN, balancedInner, parenGroups, splitStatements, splitTopLevel, unquoteIdent } from "./sql-tokenizer.js";
import type { SqlStatement } from "./sql-tokenizer.js";
import { applyDdlExtras } from "./sql-model-objects.js";
import { qualified } from "./sql-model-types.js";
import type { FunctionInfo, GrantInfo, PrivEvent, TriggerInfo, ViewInfo } from "./sql-model-types.js";

export { qualified } from "./sql-model-types.js";
export type { FunctionInfo, GrantInfo, PrivEvent, TriggerInfo, ViewInfo } from "./sql-model-types.js";

export interface Located {
  readonly file: string;
  readonly line: number;
  readonly snippet: string;
}

export interface TableInfo extends Located {
  readonly schema: string;
  readonly name: string;
  readonly columns: Set<string>;
  rlsEnabled: boolean;
  /** True when the table's `id` column references auth.users (the Supabase `profiles` pattern). */
  idRefsAuthUsers: boolean;
}

export interface PolicyInfo extends Located {
  readonly name: string;
  readonly tableKey: string;
  readonly roles: readonly string[];
  readonly command: string;
  readonly restrictive: boolean;
  readonly using: string | null;
  readonly check: string | null;
}

export interface BucketInfo extends Located {
  readonly name: string;
  isPublic: boolean;
  readonly source?: "config";
}

export interface SqlModel {
  readonly tables: Map<string, TableInfo>;
  /** RLS state per table key, independent of whether/when the table was created in the repo. */
  readonly rls: Map<string, boolean>;
  readonly policies: PolicyInfo[];
  readonly functions: Map<string, FunctionInfo>;
  readonly views: Map<string, ViewInfo>;
  readonly triggers: TriggerInfo[];
  readonly grants: GrantInfo[];
  readonly privEvents: PrivEvent[];
  readonly buckets: Map<string, BucketInfo>;
  /** Columns / id-reference seen in ALTER TABLE before the CREATE TABLE was processed. */
  readonly pending: Map<string, { columns: Set<string>; idRefsAuthUsers: boolean }>;
  /** `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS`: new functions start revoked. */
  defaultFunctionsRevoked: boolean;
}

export const SNIPPET_MAX = 200;

export function tableKey(schemaOrName: string, name?: string): string {
  return name === undefined ? `public.${unquoteIdent(schemaOrName)}` : `${unquoteIdent(schemaOrName)}.${unquoteIdent(name)}`;
}

export function snippetOf(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > SNIPPET_MAX ? `${flat.slice(0, SNIPPET_MAX - 3)}...` : flat;
}

const RE = {
  temp: /^create\s+(?:global\s+|local\s+)?(?:temp|temporary)\b/i,
  createTable: new RegExp(`^create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${QN}\\s*\\(`, "i"),
  dropTable: new RegExp(`^drop\\s+table\\s+(?:if\\s+exists\\s+)?([\\s\\S]+)$`, "i"),
  alterTable: new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${QN}\\s+([\\s\\S]*)$`, "i"),
  rls: /\b(enable|disable)\s+row\s+level\s+security\b/gi,
  addColumn: new RegExp(`\\badd\\s+(?:column\\s+)?(?:if\\s+not\\s+exists\\s+)?(${ID})\\s+\\w`, "gi"),
  idFk: /foreign\s+key\s*\(\s*"?id"?\s*\)\s*references\s+"?auth"?\s*\.\s*"?users"?/i,
  authUsersRef: /\breferences\s+"?auth"?\s*\.\s*"?users"?/i,
  policy: new RegExp(`^create\\s+policy\\s+(${ID})\\s+on\\s+${QN}([\\s\\S]*)$`, "i"),
  alterPolicy: new RegExp(`^alter\\s+policy\\s+(${ID})\\s+on\\s+${QN}([\\s\\S]*)$`, "i"),
  dropPolicy: new RegExp(`^drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${ID})\\s+on\\s+${QN}`, "i"),
  insertBucket: /^insert\s+into\s+"?storage"?\s*\.\s*"?buckets"?\s*\(([^)]*)\)\s*values\s*([\s\S]*)$/i,
  updateBucket: /^update\s+"?storage"?\s*\.\s*"?buckets"?\s+set\s+([\s\S]*?)(?:\s+where\s+([\s\S]*))?$/i,
};

const CONSTRAINT_START = /^(constraint|primary|foreign|unique|check|like|exclude)\b/i;

function parseColumns(skeleton: string, openIdx: number): { cols: string[]; idRefsAuthUsers: boolean } {
  const inner = balancedInner(skeleton, openIdx);
  if (inner === null) return { cols: [], idRefsAuthUsers: false };
  const cols: string[] = [];
  let idRef = false;
  for (const item of splitTopLevel(inner, ",")) {
    if (!item) continue;
    if (CONSTRAINT_START.test(item)) {
      if (RE.idFk.test(item)) idRef = true;
      continue;
    }
    const m = new RegExp(`^(${ID})`).exec(item);
    if (!m?.[1]) continue;
    const col = unquoteIdent(m[1]);
    cols.push(col);
    if (col === "id" && RE.authUsersRef.test(item)) idRef = true;
  }
  return { cols, idRefsAuthUsers: idRef };
}

function onCreateTable(st: SqlStatement, at: Located, model: SqlModel): void {
  if (RE.temp.test(st.skeleton)) return;
  const m = RE.createTable.exec(st.skeleton);
  if (!m?.[1]) return;
  const { schema, name } = qualified(m[1], m[2]);
  const key = `${schema}.${name}`;
  if (model.tables.has(key) && /^create\s+(?:unlogged\s+)?table\s+if\s+not\s+exists\b/i.test(st.skeleton)) return;
  const parsed = parseColumns(st.skeleton, m[0].length - 1);
  const columns = new Set(parsed.cols);
  const pend = model.pending.get(key);
  for (const c of pend?.columns ?? []) columns.add(c);
  model.pending.delete(key);
  model.tables.set(key, {
    ...at, schema, name, columns, rlsEnabled: false, idRefsAuthUsers: parsed.idRefsAuthUsers || (pend?.idRefsAuthUsers ?? false),
  });
}

function onAlterTable(st: SqlStatement, model: SqlModel): void {
  const m = RE.alterTable.exec(st.skeleton);
  if (!m?.[1]) return;
  const { schema, name } = qualified(m[1], m[2]);
  const key = `${schema}.${name}`;
  const rest = m[3] ?? "";
  let rls: RegExpExecArray | null;
  RE.rls.lastIndex = 0;
  while ((rls = RE.rls.exec(rest))) model.rls.set(key, rls[1]?.toLowerCase() === "enable");
  const table = model.tables.get(key);
  const pend = table ? null : (model.pending.get(key) ?? { columns: new Set<string>(), idRefsAuthUsers: false });
  if (pend) model.pending.set(key, pend);
  RE.addColumn.lastIndex = 0;
  let col: RegExpExecArray | null;
  while ((col = RE.addColumn.exec(rest))) {
    const id = unquoteIdent(col[1] as string);
    if (CONSTRAINT_START.test(id)) continue;
    (table?.columns ?? pend?.columns)?.add(id);
  }
  if (RE.idFk.test(rest) || (/\badd\s+(?:column\s+)?"?id"?\s/i.test(rest) && RE.authUsersRef.test(rest))) {
    if (table) table.idRefsAuthUsers = true;
    else if (pend) pend.idRefsAuthUsers = true;
  }
}

function dropTableKey(key: string, model: SqlModel): void {
  model.tables.delete(key);
  model.rls.delete(key);
  model.pending.delete(key);
  for (let i = model.policies.length - 1; i >= 0; i--) if (model.policies[i]?.tableKey === key) model.policies.splice(i, 1);
}

function onDropTable(st: SqlStatement, model: SqlModel): void {
  const m = RE.dropTable.exec(st.skeleton);
  if (!m?.[1]) return;
  for (const part of m[1].split(",")) {
    const q = new RegExp(`^\\s*${QN}`).exec(part);
    if (!q?.[1]) continue;
    const { schema, name } = qualified(q[1], q[2]);
    dropTableKey(`${schema}.${name}`, model);
  }
}

function parseRoles(header: string): string[] | null {
  const m = /\bto\s+([\s\S]+)$/i.exec(header);
  if (!m?.[1]) return null;
  return m[1].split(",").map((r) => unquoteIdent(r)).filter(Boolean);
}

function grabClause(rest: string, re: RegExp): string | null {
  const hit = re.exec(rest);
  return hit ? balancedInner(rest, hit.index + hit[0].length - 1) : null;
}

/** Policies are parsed from `text` (not the skeleton) so string literals such as 'authenticated' survive. */
function onPolicy(st: SqlStatement, at: Located, model: SqlModel): void {
  const m = RE.policy.exec(st.text);
  if (!m?.[1] || !m[2]) return;
  const { schema, name: table } = qualified(m[2], m[3]);
  const rest = m[4] ?? "";
  const clauseAt = rest.search(/\b(using|with\s+check)\s*\(/i);
  const header = clauseAt === -1 ? rest : rest.slice(0, clauseAt);
  model.policies.push({
    ...at,
    name: unquoteIdent(m[1]),
    tableKey: `${schema}.${table}`,
    roles: parseRoles(header) ?? ["public"],
    command: /\bfor\s+(all|select|insert|update|delete)\b/i.exec(header)?.[1]?.toLowerCase() ?? "all",
    restrictive: /\bas\s+restrictive\b/i.test(header),
    using: grabClause(rest, /\busing\s*\(/i),
    check: grabClause(rest, /\bwith\s+check\s*\(/i),
  });
}

function onAlterPolicy(st: SqlStatement, model: SqlModel): void {
  const m = RE.alterPolicy.exec(st.text);
  if (!m?.[1] || !m[2]) return;
  const { schema, name: table } = qualified(m[2], m[3]);
  const key = `${schema}.${table}`;
  const pname = unquoteIdent(m[1]);
  const rest = m[4] ?? "";
  const idx = model.policies.findIndex((p) => p.tableKey === key && p.name === pname);
  const prev = model.policies[idx];
  if (!prev) return;
  const rename = new RegExp(`^\\s*rename\\s+to\\s+(${ID})`, "i").exec(rest);
  const clauseAt = rest.search(/\b(using|with\s+check)\s*\(/i);
  const header = clauseAt === -1 ? rest : rest.slice(0, clauseAt);
  const using = grabClause(rest, /\busing\s*\(/i);
  const check = grabClause(rest, /\bwith\s+check\s*\(/i);
  model.policies[idx] = {
    ...prev,
    name: rename?.[1] ? unquoteIdent(rename[1]) : prev.name,
    roles: parseRoles(header) ?? prev.roles,
    using: using ?? prev.using,
    check: check ?? prev.check,
  };
}

function onDropPolicy(st: SqlStatement, model: SqlModel): void {
  const m = RE.dropPolicy.exec(st.skeleton);
  if (!m?.[1] || !m[2]) return;
  const { schema, name: table } = qualified(m[2], m[3]);
  const key = `${schema}.${table}`;
  const pname = unquoteIdent(m[1]);
  for (let i = model.policies.length - 1; i >= 0; i--) {
    const p = model.policies[i];
    if (p?.tableKey === key && p.name === pname) model.policies.splice(i, 1);
  }
}

function unquoteValue(v: string): string {
  const t = v.trim();
  return t.startsWith("'") && t.endsWith("'") && t.length >= 2 ? t.slice(1, -1).replace(/''/g, "'") : t;
}

function setBucket(model: SqlModel, name: string, isPublic: boolean, at: Located): void {
  const prev = model.buckets.get(name);
  if (prev) prev.isPublic = isPublic;
  else model.buckets.set(name, { ...at, name, isPublic });
}

function onBucket(st: SqlStatement, at: Located, model: SqlModel): void {
  const ins = RE.insertBucket.exec(st.text);
  if (ins?.[1] && ins[2] !== undefined) {
    const cols = ins[1].split(",").map((c) => unquoteIdent(c));
    const pub = cols.indexOf("public");
    const idIdx = cols.indexOf("id") !== -1 ? cols.indexOf("id") : cols.indexOf("name");
    if (idIdx === -1) return;
    for (const group of parenGroups(ins[2])) {
      const vals = splitTopLevel(group, ",");
      const name = unquoteValue(vals[idIdx] ?? "");
      if (name) setBucket(model, name, pub !== -1 && /^true$/i.test((vals[pub] ?? "").trim()), at);
    }
    return;
  }
  const upd = RE.updateBucket.exec(st.text);
  if (!upd?.[1] || !upd[2]) return;
  const flag = /\bpublic\s*=\s*(true|false)\b/i.exec(upd[1]);
  const id = /\b(?:id|name)\s*=\s*'([^']+)'/i.exec(upd[2]);
  if (flag?.[1] && id?.[1]) setBucket(model, id[1], flag[1].toLowerCase() === "true", at);
}

function applyStatement(st: SqlStatement, file: string, model: SqlModel): void {
  const at: Located = { file, line: st.line, snippet: snippetOf(st.text) };
  const head = st.skeleton.slice(0, 40).toLowerCase();
  if (head.startsWith("create policy")) onPolicy(st, at, model);
  else if (head.startsWith("alter policy")) onAlterPolicy(st, model);
  else if (head.startsWith("drop policy")) onDropPolicy(st, model);
  else if (/^create\s+(unlogged\s+)?(global\s+|local\s+)?(temp(orary)?\s+)?table/.test(head)) onCreateTable(st, at, model);
  else if (head.startsWith("alter table")) onAlterTable(st, model);
  else if (head.startsWith("drop table")) onDropTable(st, model);
  else if (/^(insert into|update)\s+"?storage"?/.test(head)) onBucket(st, at, model);
  else applyDdlExtras(st, at, model);
}

/** Builds a model from SQL files in order. Each statement is isolated: a failure never aborts the scan. */
export function buildModel(files: readonly { path: string; content: string }[]): SqlModel {
  const model: SqlModel = {
    tables: new Map(), rls: new Map(), policies: [], functions: new Map(), views: new Map(), triggers: [],
    grants: [], privEvents: [], buckets: new Map(), pending: new Map(), defaultFunctionsRevoked: false,
  };
  for (const f of files) {
    for (const st of splitStatements(f.content)) {
      try {
        applyStatement(st, f.path, model);
      } catch {
        /* unparseable statement: skip */
      }
    }
  }
  for (const [key, t] of model.tables) t.rlsEnabled = model.rls.get(key) ?? false;
  return model;
}
