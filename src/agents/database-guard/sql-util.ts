import { balancedInner } from "./sql-tokenizer.js";
import { ownerColumn } from "./fixes.js";
import type { Located, PolicyInfo, SqlModel, TableInfo } from "./sql-model.js";

export const OPEN_ROLES = new Set(["anon", "public", "authenticated"]);
export const IDENTITY_FN = /\bauth\s*\.\s*(uid|jwt)\s*\(/i;

export function ev(at: Located): readonly [{ file: string; line: number; snippet: string }] {
  return [{ file: at.file, line: at.line, snippet: at.snippet }];
}

/** Owner column of a table, counting `id` when it references auth.users. */
export function ownerOf(t: TableInfo): string | undefined {
  return ownerColumn(t.columns, { idIsAuthUser: t.idRefsAuthUsers });
}

export function unwrapParens(expr: string): string {
  let e = expr.trim();
  while (e.startsWith("(") && e.endsWith(")") && balancedInner(e, 0)?.length === e.length - 2) e = e.slice(1, -1).trim();
  return e;
}

export function isTrivialTrue(expr: string | null): boolean {
  if (expr === null) return false;
  return /^(true|1\s*=\s*1)$/i.test(unwrapParens(expr));
}

/** Condition that only proves "signed in" (any free sign-up passes): auth.uid() IS NOT NULL, auth.role() = 'authenticated'. */
function isAuthOnlyExpr(expr: string): boolean {
  const unwrapped = unwrapParens(expr).replace(/\(\s*select\s+(auth\s*\.\s*\w+\s*\(\s*\))\s*\)/gi, "$1");
  const c = unwrapParens(unwrapped).replace(/\s+/g, "").toLowerCase();
  return /^auth\.uid\(\)isnotnull$/.test(c)
    || /^auth\.role\(\)='authenticated'$/.test(c)
    || /^\(?auth\.jwt\(\)->>'role'\)?='authenticated'$/.test(c);
}

export function isAuthOnlyPolicy(p: PolicyInfo): boolean {
  const parts = [p.using, p.check].filter((x): x is string => x !== null);
  return parts.length > 0 && parts.every(isAuthOnlyExpr);
}

/** True if the expression ties the row to the caller (auth.uid() beyond IS NOT NULL, an owner column, a folder check). */
export function hasOwnerCheck(expr: string): boolean {
  const e = expr.replace(/auth\s*\.\s*uid\s*\(\s*\)\s+is\s+not\s+null/gi, "");
  return /\bauth\s*\.\s*uid\s*\(/i.test(e) || /\bowner(_id)?\b/i.test(e) || /\bstorage\s*\.\s*foldername\s*\(/i.test(e);
}

export function words(expr: string): Set<string> {
  return new Set(expr.toLowerCase().match(/[a-z_][a-z0-9_]*/g) ?? []);
}

export function displayFn(f: { schema: string; name: string }): string {
  return f.schema === "public" ? f.name : `${f.schema}.${f.name}`;
}

/**
 * Is `column` still writable/readable by API roles? Walks GRANT/REVOKE events for the table in order:
 * a table-level revoke or a column grant list that excludes the column protects it.
 */
export function columnProtected(model: SqlModel, t: TableInfo, column: string, priv: "update" | "select"): boolean {
  let open = true;
  for (const e of model.privEvents) {
    if (e.priv !== priv || !e.roles.some((r) => OPEN_ROLES.has(r))) continue;
    const applies = (e.object.kind === "table" && e.object.key === `${t.schema}.${t.name}`)
      || (e.object.kind === "allTables" && e.object.schema === t.schema);
    if (!applies) continue;
    if (e.kind === "revoke") {
      if (e.columns === null || e.columns.includes(column)) open = false;
    } else open = e.columns === null || e.columns.includes(column);
  }
  return !open;
}
