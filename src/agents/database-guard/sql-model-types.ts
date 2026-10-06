import { unquoteIdent } from "./sql-tokenizer.js";
import type { Located } from "./sql-model.js";

export function qualified(a: string, b: string | undefined): { schema: string; name: string } {
  return b === undefined
    ? { schema: "public", name: unquoteIdent(a) }
    : { schema: unquoteIdent(a), name: unquoteIdent(b) };
}

export interface FunctionInfo extends Located {
  readonly schema: string;
  readonly name: string;
  /** Number of declared parameters: overloads are keyed by arity. */
  readonly arity: number;
  /** Parameter list as written, defaults stripped (usable in ALTER/REVOKE statements). */
  readonly args: string;
  readonly securityDefiner: boolean;
  hasSearchPath: boolean;
  readonly returns: string;
  readonly takesUuid: boolean;
  /** Full statement text including the dollar-quoted body. */
  readonly body: string;
  /** True once a REVOKE took EXECUTE away from public/anon/authenticated. */
  revoked: boolean;
}

export interface ViewInfo extends Located {
  readonly schema: string;
  readonly name: string;
  securityInvoker: boolean;
  readonly selectsAuthUsers: boolean;
  readonly revokedRoles: Set<string>;
}

export interface TriggerInfo extends Located {
  readonly name: string;
  readonly tableKey: string;
  readonly beforeUpdate: boolean;
  readonly text: string;
  readonly functionName: string;
}

/** Write privileges granted to anon on one object (one entry per object of a GRANT statement). */
export interface GrantInfo extends Located {
  readonly object: TableRef;
  readonly privs: Set<string>;
}

export type TableRef =
  | { readonly kind: "table"; readonly key: string }
  | { readonly kind: "allTables"; readonly schema: string }
  | { readonly kind: "defaultTables" };

/** An UPDATE or SELECT grant/revoke on a table, used to decide whether a column is protected. */
export interface PrivEvent {
  readonly kind: "grant" | "revoke";
  readonly priv: "update" | "select";
  readonly object: TableRef;
  /** Column list for column-level privileges, null for table-level. */
  readonly columns: readonly string[] | null;
  readonly roles: readonly string[];
}
