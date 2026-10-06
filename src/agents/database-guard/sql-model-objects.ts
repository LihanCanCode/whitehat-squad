import { ID, QN, balancedInner, splitTopLevel, unquoteIdent } from "./sql-tokenizer.js";
import type { SqlStatement } from "./sql-tokenizer.js";
import { qualified } from "./sql-model-types.js";
import type { FunctionInfo, GrantInfo, TableRef } from "./sql-model-types.js";
import type { Located, SqlModel } from "./sql-model.js";

/** Functions, views, triggers and privileges (GRANT / REVOKE / ALTER DEFAULT PRIVILEGES). */

const WRITE_PRIVS = ["insert", "update", "delete", "truncate"] as const;
const ALL_PRIVS = ["select", "insert", "update", "delete", "truncate", "references", "trigger", "execute", "usage"];
const COLUMN_PRIVS = ["update", "select"] as const;
const API_ROLES = new Set(["public", "anon", "authenticated"]);

interface FnRef {
  readonly schema: string;
  readonly name: string;
  readonly arity: number | null;
  readonly args: string;
  readonly uuid: boolean;
  readonly end: number;
}

function stripDefault(item: string): string {
  return item.replace(/\s+(?:default\b|=)[\s\S]*$/i, "").trim();
}

/** Parses `[schema.]name[(args)]` at the start of `s`. */
function fnRef(s: string): FnRef | null {
  const m = new RegExp(`^\\s*${QN}`).exec(s);
  if (!m?.[1]) return null;
  const { schema, name } = qualified(m[1], m[2]);
  const open = /^\s*\(/.exec(s.slice(m[0].length));
  if (!open) return { schema, name, arity: null, args: "", uuid: false, end: m[0].length };
  const idx = m[0].length + open[0].length - 1;
  const inner = balancedInner(s, idx);
  if (inner === null) return { schema, name, arity: null, args: "", uuid: false, end: m[0].length };
  const items = splitTopLevel(inner, ",").filter(Boolean);
  return {
    schema, name, arity: items.length, args: items.map(stripDefault).join(", "), uuid: /\buuid\b/i.test(inner),
    end: idx + inner.length + 2,
  };
}

/** The function body only (from AS $ / AS ' on), so the signature never counts as body text. */
function bodyOf(text: string): string {
  const at = text.search(/ass+(?:$[A-Za-z0-9_]*$|')/i);
  return at === -1 ? text : text.slice(at);
}

const fnKey = (schema: string, name: string, arity: number): string => `${schema}.${name}/${arity}`;

function matchingFunctions(model: SqlModel, ref: { schema: string; name: string; arity: number | null }): FunctionInfo[] {
  return [...model.functions.values()].filter(
    (f) => f.schema === ref.schema && f.name === ref.name && (ref.arity === null || f.arity === ref.arity),
  );
}

function onCreateFunction(st: SqlStatement, at: Located, model: SqlModel): void {
  const head = /^create\s+(or\s+replace\s+)?function\s+/i.exec(st.skeleton);
  if (!head) return;
  const rest = st.skeleton.slice(head[0].length);
  const ref = fnRef(rest);
  if (!ref) return;
  const arity = ref.arity ?? 0;
  const key = fnKey(ref.schema, ref.name, arity);
  const prev = model.functions.get(key);
  const returns = /\breturns\s+(?:setof\s+)?("?[\w.]+"?)/i.exec(rest.slice(ref.end))?.[1]?.replace(/"/g, "").toLowerCase() ?? "";
  model.functions.set(key, {
    ...at, schema: ref.schema, name: ref.name, arity, args: ref.args, returns, takesUuid: ref.uuid,
    securityDefiner: /\bsecurity\s+definer\b/i.test(st.skeleton),
    hasSearchPath: /\bset\s+search_path\b/i.test(st.skeleton),
    body: bodyOf(st.text),
    revoked: head[1] && prev ? prev.revoked : model.defaultFunctionsRevoked,
  });
}

function onAlterFunction(st: SqlStatement, model: SqlModel): void {
  const head = /^alter\s+function\s+/i.exec(st.skeleton);
  if (!head) return;
  const rest = st.skeleton.slice(head[0].length);
  const ref = fnRef(rest);
  if (!ref || !/\bset\s+search_path\b/i.test(rest.slice(ref.end))) return;
  for (const fn of matchingFunctions(model, ref)) fn.hasSearchPath = true;
}

function onDropFunction(st: SqlStatement, model: SqlModel): void {
  const head = /^drop\s+(?:function|procedure|routine)\s+(?:if\s+exists\s+)?/i.exec(st.skeleton);
  if (!head) return;
  for (const part of splitTopLevel(st.skeleton.slice(head[0].length), ",")) {
    const ref = fnRef(part);
    if (ref) for (const fn of matchingFunctions(model, ref)) model.functions.delete(fnKey(fn.schema, fn.name, fn.arity));
  }
}

const SECURITY_INVOKER = /security_invoker\s*(?:=\s*)?(?:true|on|'true'|'on'|1)\b/i;

function onCreateView(st: SqlStatement, at: Located, model: SqlModel): void {
  const m = new RegExp(
    `^create\\s+(?:or\\s+replace\\s+)?(?:(?:global\\s+|local\\s+)?(?:temp|temporary)\\s+)?(?:recursive\\s+)?view\\s+${QN}([\\s\\S]*)$`, "i",
  ).exec(st.text);
  if (!m?.[1] || /^create\s+(?:or\s+replace\s+)?(?:global\s+|local\s+)?(?:temp|temporary)\b/i.test(st.text)) return;
  const { schema, name } = qualified(m[1], m[2]);
  const rest = m[3] ?? "";
  const asAt = rest.search(/\bas\s+(?:select|with|values|table|\()/i);
  const options = asAt === -1 ? rest : rest.slice(0, asAt);
  const key = `${schema}.${name}`;
  const prev = model.views.get(key);
  model.views.set(key, {
    ...at, schema, name,
    securityInvoker: SECURITY_INVOKER.test(options),
    selectsAuthUsers: /\b(?:from|join)\s+"?auth"?\s*\.\s*"?users"?\b/i.test(st.skeleton),
    revokedRoles: prev?.revokedRoles ?? new Set(),
  });
}

function onDropView(st: SqlStatement, model: SqlModel): void {
  const head = /^drop\s+view\s+(?:if\s+exists\s+)?/i.exec(st.skeleton);
  if (!head) return;
  for (const part of splitTopLevel(st.skeleton.slice(head[0].length), ",")) {
    const q = new RegExp(`^\\s*${QN}`).exec(part);
    if (!q?.[1]) continue;
    const { schema, name } = qualified(q[1], q[2]);
    model.views.delete(`${schema}.${name}`);
  }
}

function onAlterView(st: SqlStatement, model: SqlModel): void {
  const m = new RegExp(`^alter\\s+view\\s+(?:if\\s+exists\\s+)?${QN}\\s+(set|reset)\\s*\\(([\\s\\S]*)\\)`, "i").exec(st.text);
  if (!m?.[1]) return;
  const { schema, name } = qualified(m[1], m[2]);
  const view = model.views.get(`${schema}.${name}`);
  if (!view || !/security_invoker/i.test(m[4] ?? "")) return;
  view.securityInvoker = m[3]?.toLowerCase() === "set" && SECURITY_INVOKER.test(m[4] ?? "");
}

function onCreateTrigger(st: SqlStatement, at: Located, model: SqlModel): void {
  const m = new RegExp(
    `^create\\s+(?:or\\s+replace\\s+)?(?:constraint\\s+)?trigger\\s+(${ID})\\s+(before|after|instead\\s+of)\\s+([\\s\\S]*?)\\s+on\\s+${QN}([\\s\\S]*)$`, "i",
  ).exec(st.skeleton);
  if (!m?.[1] || !m[2] || !m[4]) return;
  const { schema, name } = qualified(m[4], m[5]);
  const fn = new RegExp(`\\bexecute\\s+(?:function|procedure)\\s+${QN}`, "i").exec(m[6] ?? "");
  model.triggers.push({
    ...at, name: unquoteIdent(m[1]), tableKey: `${schema}.${name}`,
    beforeUpdate: m[2].toLowerCase() === "before" && /\bupdate\b/i.test(m[3] ?? ""),
    text: st.text, functionName: fn?.[1] ? qualified(fn[1], fn[2]).name : "",
  });
}

function onDropTrigger(st: SqlStatement, model: SqlModel): void {
  const m = new RegExp(`^drop\\s+trigger\\s+(?:if\\s+exists\\s+)?(${ID})\\s+on\\s+${QN}`, "i").exec(st.skeleton);
  if (!m?.[1] || !m[2]) return;
  const { schema, name } = qualified(m[2], m[3]);
  const trig = unquoteIdent(m[1]);
  for (let i = model.triggers.length - 1; i >= 0; i--) {
    const t = model.triggers[i];
    if (t?.name === trig && t.tableKey === `${schema}.${name}`) model.triggers.splice(i, 1);
  }
}

type Obj =
  | TableRef
  | { readonly kind: "function"; readonly schema: string; readonly name: string; readonly arity: number | null }
  | { readonly kind: "allFunctions"; readonly schema: string }
  | { readonly kind: "defaultFunctions" };

const IGNORED_OBJECT = /^(?:all\s+(?:sequences|procedures|routines)\s+in|sequences?|schema|database|type|domain|language|foreign|large|tablespace|parameter)\b/i;

function parseObjects(raw: string, isDefault: boolean): Obj[] {
  const t = raw.trim().replace(/\s+/g, " ");
  if (isDefault) {
    if (/^tables$/i.test(t)) return [{ kind: "defaultTables" }];
    if (/^functions$/i.test(t)) return [{ kind: "defaultFunctions" }];
    return [];
  }
  const allT = /^all\s+tables\s+in\s+schema\s+(.+)$/i.exec(t);
  if (allT?.[1]) return allT[1].split(",").map((s) => ({ kind: "allTables", schema: unquoteIdent(s) }));
  const allF = /^all\s+functions\s+in\s+schema\s+(.+)$/i.exec(t);
  if (allF?.[1]) return allF[1].split(",").map((s) => ({ kind: "allFunctions", schema: unquoteIdent(s) }));
  const fns = /^(?:function|procedure|routine)\s+(.+)$/i.exec(t);
  if (fns?.[1]) {
    const out: Obj[] = [];
    for (const part of splitTopLevel(fns[1], ",")) {
      const ref = fnRef(part);
      if (ref) out.push({ kind: "function", schema: ref.schema, name: ref.name, arity: ref.arity });
    }
    return out;
  }
  if (IGNORED_OBJECT.test(t)) return [];
  const out: Obj[] = [];
  for (const part of t.replace(/^table\s+/i, "").split(",")) {
    const q = new RegExp(`^\\s*${QN}\\s*$`).exec(part);
    if (!q?.[1]) continue;
    const { schema, name } = qualified(q[1], q[2]);
    out.push({ kind: "table", key: `${schema}.${name}` });
  }
  return out;
}

interface PrivStmt {
  readonly privs: Set<string>;
  readonly columns: Map<string, string[]>;
  readonly objects: Obj[];
  readonly roles: string[];
}

function parsePrivs(text: string): { privs: Set<string>; columns: Map<string, string[]> } {
  const privs = new Set<string>();
  const columns = new Map<string, string[]>();
  for (const token of splitTopLevel(text, ",")) {
    const cols = /\(([^)]*)\)/.exec(token)?.[1];
    const base = token.replace(/\([^)]*\)/g, "").trim().toLowerCase().replace(/\s+privileges$/, "");
    if (!base) continue;
    for (const p of base === "all" ? ALL_PRIVS : [base]) {
      privs.add(p);
      if (cols) columns.set(p, cols.split(",").map((c) => unquoteIdent(c)).filter(Boolean));
    }
  }
  return { privs, columns };
}

function parsePrivStatement(sk: string, verb: "grant" | "revoke", isDefault: boolean): PrivStmt | null {
  const re = verb === "grant"
    ? /^grant\s+([\s\S]{1,500}?)\s+on\s+([\s\S]{1,500}?)\s+to\s+([\s\S]{1,1000})$/i
    : /^revoke\s+(?:grant\s+option\s+for\s+)?([\s\S]{1,500}?)\s+on\s+([\s\S]{1,500}?)\s+from\s+([\s\S]{1,1000})$/i;
  const m = re.exec(sk);
  if (!m?.[1] || !m[2] || !m[3]) return null;
  const roleText = m[3]
    .replace(/\bwith\s+grant\s+option\b/i, "").replace(/\bgranted\s+by\s+\S+/i, "").replace(/\b(?:cascade|restrict)\s*$/i, "");
  const { privs, columns } = parsePrivs(m[1]);
  return {
    privs, columns, objects: parseObjects(m[2], isDefault),
    roles: roleText.split(",").map((r) => unquoteIdent(r.replace(/^\s*group\s+/i, ""))).filter(Boolean),
  };
}

const isTableRef = (o: Obj): o is TableRef => o.kind === "table" || o.kind === "allTables" || o.kind === "defaultTables";

function grantMatches(g: TableRef, r: TableRef): boolean {
  if (g.kind === "defaultTables") return r.kind === "defaultTables";
  if (r.kind === "table") return g.kind === "table" && g.key === r.key;
  if (r.kind === "allTables") {
    return (g.kind === "allTables" && g.schema === r.schema) || (g.kind === "table" && g.key.startsWith(`${r.schema}.`));
  }
  return false;
}

function onGrant(at: Located, model: SqlModel, isDefault: boolean, sk: string): void {
  const p = parsePrivStatement(sk, "grant", isDefault);
  if (!p) return;
  const tables = p.objects.filter(isTableRef);
  const write = WRITE_PRIVS.filter((w) => p.privs.has(w));
  if (p.roles.includes("anon") && write.length > 0) {
    for (const object of tables) model.grants.push({ ...at, object, privs: new Set(write) });
  }
  for (const priv of COLUMN_PRIVS) {
    if (!p.privs.has(priv)) continue;
    for (const object of tables) model.privEvents.push({ kind: "grant", priv, object, columns: p.columns.get(priv) ?? null, roles: p.roles });
  }
}

function revokeFunctions(p: PrivStmt, model: SqlModel): void {
  if (!p.privs.has("execute") || !p.roles.some((r) => API_ROLES.has(r))) return;
  for (const o of p.objects) {
    if (o.kind === "defaultFunctions") model.defaultFunctionsRevoked = true;
    else if (o.kind === "allFunctions") {
      for (const f of model.functions.values()) if (f.schema === o.schema) f.revoked = true;
    } else if (o.kind === "function") {
      for (const f of matchingFunctions(model, o)) f.revoked = true;
    }
  }
}

function revokeViews(p: PrivStmt, tables: TableRef[], model: SqlModel): void {
  if (!p.privs.has("select")) return;
  for (const v of model.views.values()) {
    const hit = tables.some((o) => (o.kind === "table" ? o.key === `${v.schema}.${v.name}` : o.kind === "allTables" && o.schema === v.schema));
    if (hit) for (const r of p.roles) v.revokedRoles.add(r);
  }
}

function onRevoke(sk: string, model: SqlModel, isDefault: boolean): void {
  const p = parsePrivStatement(sk, "revoke", isDefault);
  if (!p) return;
  const tables = p.objects.filter(isTableRef);
  if (p.roles.includes("anon")) {
    for (let i = model.grants.length - 1; i >= 0; i--) {
      const g = model.grants[i] as GrantInfo;
      if (tables.some((r) => grantMatches(g.object, r))) for (const priv of p.privs) g.privs.delete(priv);
      if (g.privs.size === 0) model.grants.splice(i, 1);
    }
  }
  for (const priv of COLUMN_PRIVS) {
    if (!p.privs.has(priv)) continue;
    for (const object of tables) model.privEvents.push({ kind: "revoke", priv, object, columns: p.columns.get(priv) ?? null, roles: p.roles });
  }
  revokeFunctions(p, model);
  revokeViews(p, tables, model);
}

export function applyDdlExtras(st: SqlStatement, at: Located, model: SqlModel): void {
  const sk = st.skeleton;
  const head = sk.slice(0, 60).toLowerCase();
  if (/^create\s+(or\s+replace\s+)?function\b/.test(head)) onCreateFunction(st, at, model);
  else if (/^alter\s+function\b/.test(head)) onAlterFunction(st, model);
  else if (/^drop\s+(function|procedure|routine)\b/.test(head)) onDropFunction(st, model);
  else if (/^create\s+(or\s+replace\s+)?((global\s+|local\s+)?(temp|temporary)\s+)?(recursive\s+)?view\b/.test(head)) onCreateView(st, at, model);
  else if (/^drop\s+view\b/.test(head)) onDropView(st, model);
  else if (/^alter\s+view\b/.test(head)) onAlterView(st, model);
  else if (/^create\s+(or\s+replace\s+)?(constraint\s+)?trigger\b/.test(head)) onCreateTrigger(st, at, model);
  else if (/^drop\s+trigger\b/.test(head)) onDropTrigger(st, model);
  else if (/^grant\b/.test(head)) onGrant(at, model, false, sk);
  else if (/^revoke\b/.test(head)) onRevoke(sk, model, false);
  else if (/^alter\s+default\s+privileges\b/.test(head)) {
    const v = /\b(grant|revoke)\b/i.exec(sk);
    if (!v) return;
    if (v[1]?.toLowerCase() === "grant") onGrant(at, model, true, sk.slice(v.index));
    else onRevoke(sk.slice(v.index), model, true);
  }
}
