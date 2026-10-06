import { makeFinding } from "../../core/finding.js";
import type { Finding, Severity } from "../../core/types.js";
import { AGENT_ID, qtable } from "./fixes.js";
import {
  definerExecFix, escalationFix, policyNoRlsFix, sensitiveColumnsFix, signedInOnlyFix, storagePolicyFix, userMetadataFix, viewFix,
} from "./fixes-extra.js";
import type { PolicyInfo, SqlModel, TableInfo } from "./sql-model.js";
import {
  IDENTITY_FN, OPEN_ROLES, columnProtected, displayFn, ev, hasOwnerCheck, isAuthOnlyPolicy, isTrivialTrue, ownerOf, words,
} from "./sql-util.js";

type Emit = (f: Finding) => void;

const USER_META = /\b(?:raw_user_meta_data|raw_user_metadata|user_metadata|user_meta_data)\b/i;
const META_ROLE_CHECK = new RegExp(
  `(?:${USER_META.source})[^;]{0,120}\\b(?:role|admin|is_admin|is_superuser|permissions?)\\b|\\b(?:role|admin|is_admin|is_superuser|permissions?)\\b[^;]{0,120}(?:${USER_META.source})`, "i",
);

const apiRole = (p: PolicyInfo): boolean => p.roles.some((r) => OPEN_ROLES.has(r));

/** DB-012: authorization decided from user-editable metadata (splinter 0015). */
export function ruleUserMetadata(model: SqlModel, target: string, emit: Emit): void {
  for (const p of model.policies) {
    if (p.restrictive || p.roles.every((r) => r === "service_role")) continue;
    if (!USER_META.test(`${p.using ?? ""} ${p.check ?? ""}`)) continue;
    emit(makeFinding({
      ruleId: "DB-012", agentId: AGENT_ID, target, severity: "critical", cwe: "CWE-639",
      title: `Policy "${p.name}" on ${p.tableKey} trusts user_metadata`,
      explanation: `The policy "${p.name}" decides access from user_metadata / raw_user_meta_data. That field is writable by the signed-in user themself (supabase.auth.updateUser), so any user can set role = admin on their own account and pass this check, gaining access to everyone's data. app_metadata is the safe, server-only alternative.`,
      evidence: ev(p), fix: userMetadataFix(`policy "${p.name}" on ${p.tableKey}`, "policy"),
    }));
  }
  for (const f of model.functions.values()) {
    if (!f.securityDefiner || !META_ROLE_CHECK.test(f.body)) continue;
    emit(makeFinding({
      ruleId: "DB-012", agentId: AGENT_ID, target, severity: "critical", cwe: "CWE-639",
      title: `SECURITY DEFINER function ${displayFn(f)} trusts user_metadata for a role check`,
      explanation: `The function ${displayFn(f)} runs with elevated rights and decides a role or permission from user_metadata / raw_user_meta_data. Users can edit that field on their own account, so anyone can claim to be an admin and pass the check. Use app_metadata or a roles table that only the server can write.`,
      evidence: ev(f), fix: userMetadataFix(`function ${displayFn(f)}`, "function"),
    }));
  }
}

// Exact column names only: segment matching flagged `admin_notes` and `pro_tips` (real-corpus FPs).
const SENSITIVE_HIGH = new Set([
  "role", "roles", "user_role", "app_role", "account_role", "access_level", "permissions",
  "admin", "is_admin", "superuser", "is_superuser", "is_staff", "is_moderator",
]);
const SENSITIVE_MEDIUM = new Set([
  "credits", "credit", "credit_balance", "balance", "plan", "tier", "premium", "is_premium", "is_pro",
  "subscription_status", "subscription_tier", "verified", "is_verified", "quota", "usage_limit",
]);
// In chat/LLM tables `role` is the message author ("user" / "assistant"), not a privilege
// (a chat app's public.messages was a real-corpus false positive).
const CONVERSATION_TABLE = /(?:^|_)(?:messages?|chats?|conversations?|threads?|prompts?|completions?|turns?|transcripts?)(?:_|$)/;

function escalationSeverity(col: string, table: string): Severity | null {
  if (SENSITIVE_HIGH.has(col)) {
    return (col === "role" || col === "roles") && CONVERSATION_TABLE.test(table) ? null : "high";
  }
  return SENSITIVE_MEDIUM.has(col) ? "medium" : null;
}

function ownRowUpdate(p: PolicyInfo, t: TableInfo): boolean {
  if (p.restrictive || !["update", "all"].includes(p.command) || !p.roles.some((r) => r === "authenticated" || r === "public")) return false;
  const expr = `${p.using ?? ""}`;
  const own = new Set([ownerOf(t), "id"].filter((x): x is string => x !== undefined));
  const a = /auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s*(?:::\s*text\s*)?=\s*"?([a-z_][a-z0-9_]*)"?/i.exec(expr);
  const b = /"?([a-z_][a-z0-9_]*)"?\s*=\s*\(?\s*(?:select\s+)?auth\s*\.\s*uid\s*\(/i.exec(expr);
  return [a?.[1], b?.[1]].some((c) => c !== undefined && own.has(c.toLowerCase()));
}

function guardedByTrigger(model: SqlModel, t: TableInfo, col: string): boolean {
  const re = new RegExp(`\\b${col}\\b`, "i");
  return model.triggers.some((tr) => {
    if (tr.tableKey !== `${t.schema}.${t.name}` || !tr.beforeUpdate) return false;
    const fn = [...model.functions.values()].find((f) => f.name === tr.functionName);
    return re.test(tr.text) || (fn !== undefined && re.test(fn.body));
  });
}

/** DB-013: own-row UPDATE policy + privileged column + no column protection. */
export function ruleSelfEscalation(model: SqlModel, target: string, emit: Emit): void {
  for (const t of model.tables.values()) {
    if (t.schema !== "public" || !t.rlsEnabled) continue;
    const policy = model.policies.find((p) => p.tableKey === `${t.schema}.${t.name}` && ownRowUpdate(p, t));
    if (!policy) continue;
    const exprWords = words(`${policy.using ?? ""} ${policy.check ?? ""}`);
    const exposed = [...t.columns].filter((c) => escalationSeverity(c, t.name) !== null && !exprWords.has(c)
      && !columnProtected(model, t, c, "update") && !guardedByTrigger(model, t, c));
    if (exposed.length === 0) continue;
    const high = exposed.some((c) => escalationSeverity(c, t.name) === "high");
    const owner = ownerOf(t);
    const safe = [...t.columns].filter((c) => c !== "id" && c !== owner && !exposed.includes(c));
    const q = qtable(t.schema, t.name);
    emit(makeFinding({
      ruleId: "DB-013", agentId: AGENT_ID, target, severity: high ? "high" : "medium", cwe: "CWE-269",
      title: `Users can edit their own ${exposed.join(", ")} on ${q}`,
      explanation: `The policy "${policy.name}" lets every signed-in user UPDATE their own row in ${q}, and nothing limits which columns. Any user can therefore call the API directly and set ${exposed.join(", ")} on their own row ${high ? "to make themselves an admin" : "to give themselves free credits, a paid plan or a verified badge"}.`,
      evidence: ev(policy), fix: escalationFix(t.schema, t.name, exposed, safe),
    }));
  }
}

/** DB-014: SECURITY DEFINER function in public that anon/authenticated can execute (splinter 0028/0029). */
export function ruleDefinerExecutable(model: SqlModel, target: string, emit: Emit): void {
  for (const f of model.functions.values()) {
    if (f.schema !== "public" || !f.securityDefiner || f.revoked || /^(event_)?trigger$/.test(f.returns)) continue;
    const idor = f.takesUuid && !/\bauth\s*\.\s*uid\s*\(/i.test(f.body);
    emit(makeFinding({
      ruleId: "DB-014", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-862",
      title: `SECURITY DEFINER function ${f.name} is callable by anon and authenticated`,
      explanation: `${f.name} runs with its owner's elevated rights, lives in the public schema and is never revoked from anon/authenticated, so anyone can call it through /rest/v1/rpc/${f.name} with the public key. ${idor ? "It takes a uuid parameter and never checks auth.uid(), so a caller can pass any user id and act on that user's data. " : ""}Everything it does bypasses Row Level Security.`,
      evidence: ev(f), fix: definerExecFix(f.schema, f.name, f.args),
    }));
  }
}

/** DB-015: public views that bypass RLS (splinter 0010) or expose auth.users (0002). */
export function ruleViews(model: SqlModel, target: string, emit: Emit): void {
  for (const v of model.views.values()) {
    const closed = v.revokedRoles.has("anon") && v.revokedRoles.has("authenticated");
    if (v.schema !== "public" || v.securityInvoker || closed) continue;
    const q = qtable(v.schema, v.name);
    emit(makeFinding({
      ruleId: "DB-015", agentId: AGENT_ID, target, severity: v.selectsAuthUsers ? "critical" : "high", cwe: "CWE-284",
      title: v.selectsAuthUsers ? `View ${q} exposes auth.users` : `View ${q} ignores Row Level Security`,
      explanation: v.selectsAuthUsers
        ? `The view ${q} selects from auth.users and is readable through the API. Views run with their owner's rights, so anyone with the public key can list every user's email and account data.`
        : `The view ${q} runs with its owner's rights (no security_invoker), so it bypasses Row Level Security on the tables behind it. Anyone with the public key can read rows through the view that RLS would otherwise hide.`,
      evidence: ev(v), fix: viewFix(v.schema, v.name, v.selectsAuthUsers),
    }));
  }
}

/** DB-016: policies exist but RLS is never enabled (splinter 0007). */
export function rulePolicyWithoutRls(model: SqlModel, target: string, emit: Emit): void {
  const seen = new Set<string>();
  for (const p of model.policies) {
    const t = model.tables.get(p.tableKey);
    if (!t || t.schema !== "public" || t.rlsEnabled || seen.has(p.tableKey)) continue;
    seen.add(p.tableKey);
    const q = qtable(t.schema, t.name);
    emit(makeFinding({
      ruleId: "DB-016", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-862",
      title: `Policies on ${q} are not enforced: RLS is never enabled`,
      explanation: `${q} has policies (for example "${p.name}") but Row Level Security is never enabled on it. Policies are not enforced while RLS is off, so the author believes the table is protected while it is open: anyone with the public anon key can read and write every row.`,
      evidence: ev(p), fix: policyNoRlsFix(t.schema, t.name),
    }));
  }
}

/** DB-017 builder: the policy that proves nothing but "signed in". */
export function signedInOnlyFinding(p: PolicyInfo, t: TableInfo, owner: string, target: string): Finding {
  const q = qtable(t.schema, t.name);
  return makeFinding({
    ruleId: "DB-017", agentId: AGENT_ID, target, severity: "medium", confidence: "medium", cwe: "CWE-284",
    title: `Policy "${p.name}" on ${q} lets any signed-in user in`,
    explanation: `The policy "${p.name}" only checks that the caller is signed in. Anyone can sign up for free (or anonymously), so ${q} is effectively readable${p.command === "select" ? "" : " and writable"} by the whole internet, even though it has an owner column (${owner}) that should restrict each user to their own rows.`,
    evidence: ev(p), fix: signedInOnlyFix(p.name, t.schema, t.name, owner),
  });
}

export function isSignedInOnly(p: PolicyInfo): boolean {
  return !p.restrictive && apiRole(p) && isAuthOnlyPolicy(p);
}

const BUCKET_ONLY = /^bucket_id\s*=\s*'[^']*'$/i;
const BUCKET_REF = /bucket_id\s*=\s*'([^']+)'/gi;

function bucketsIn(expr: string): string[] {
  return [...expr.matchAll(BUCKET_REF)].map((m) => m[1] as string);
}

function writeExpr(p: PolicyInfo): string {
  return p.command === "insert" ? (p.check ?? "") : p.command === "select" ? "" : `${p.using ?? ""} ${p.check ?? ""}`;
}

/** DB-018: storage.objects policies (listing exposure 0025, unscoped writes). */
export function ruleStorageObjects(model: SqlModel, target: string, emit: Emit): void {
  for (const p of model.policies) {
    if (p.tableKey !== "storage.objects" || p.restrictive || !apiRole(p)) continue;
    const buckets = bucketsIn(`${p.using ?? ""} ${p.check ?? ""}`);
    const name = p.name;
    if (p.command !== "select" && !hasOwnerCheck(writeExpr(p))) {
      emit(makeFinding({
        ruleId: "DB-018", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-862",
        title: `Storage policy "${name}" allows ${p.command === "all" ? "writes" : p.command} without an owner check`,
        explanation: `The policy "${name}" on storage.objects lets ${p.roles.join(", ")} ${p.command === "insert" ? "upload files" : "change or delete files"}${buckets.length ? ` in "${buckets.join('", "')}"` : ""} without tying them to the uploader (no auth.uid() or folder check). Any matching user can overwrite or delete other users' files, or fill your storage with their own.`,
        evidence: ev(p), fix: storagePolicyFix(name, false),
      }));
      continue;
    }
    const onlyBucket = p.using !== null && BUCKET_ONLY.test(p.using.trim().replace(/^\((.*)\)$/s, "$1").trim());
    const publicBucket = buckets.find((b) => model.buckets.get(b)?.isPublic);
    if (["select", "all"].includes(p.command) && onlyBucket && publicBucket !== undefined) {
      emit(makeFinding({
        ruleId: "DB-018", agentId: AGENT_ID, target, severity: "medium", cwe: "CWE-200",
        title: `Storage policy "${name}" lets anyone list the public bucket "${publicBucket}"`,
        explanation: `The bucket "${publicBucket}" is public, so files are already served by URL. This SELECT policy additionally lets anyone enumerate every file name in the bucket through the Storage API, which exposes other users' uploads and makes URL guessing unnecessary.`,
        evidence: ev(p), fix: storagePolicyFix(name, true),
      }));
    }
  }
}

const SENSITIVE_COLUMN = /(?:^|_)(?:password|passwd|secret|otp|ssn|apikey|api_key|refresh_token|access_token|token)(?:_|$)/;

function broadRead(p: PolicyInfo): boolean {
  if (p.restrictive || !["select", "all"].includes(p.command) || !apiRole(p)) return false;
  return isTrivialTrue(p.using) || isAuthOnlyPolicy(p) || (p.using !== null && !IDENTITY_FN.test(p.using));
}

/** DB-019: secret-looking columns readable through a broad SELECT policy (splinter 0023). */
export function ruleSensitiveColumns(model: SqlModel, target: string, emit: Emit): void {
  for (const t of model.tables.values()) {
    if (t.schema !== "public" || !t.rlsEnabled) continue;
    const sensitive = [...t.columns].filter((c) => !/^(has|is)_/.test(c) && SENSITIVE_COLUMN.test(c)
      && !columnProtected(model, t, c, "select"));
    const policy = model.policies.find((p) => p.tableKey === `${t.schema}.${t.name}` && broadRead(p));
    if (sensitive.length === 0 || !policy) continue;
    const q = qtable(t.schema, t.name);
    const safe = [...t.columns].filter((c) => !sensitive.includes(c));
    emit(makeFinding({
      ruleId: "DB-019", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-200",
      title: `${q} exposes ${sensitive.join(", ")} through a broad read policy`,
      explanation: `${q} has columns that look like secrets (${sensitive.join(", ")}) and the policy "${policy.name}" lets ${policy.roles.join(", ")} read rows without an owner check. A single request to the REST API returns these values for every row, so tokens, keys or password hashes can be harvested.`,
      evidence: ev(policy), fix: sensitiveColumnsFix(t.schema, t.name, sensitive, safe),
    }));
  }
}

export function analyzeSupabase(model: SqlModel, target: string, emit: Emit): void {
  ruleUserMetadata(model, target, emit);
  ruleSelfEscalation(model, target, emit);
  ruleDefinerExecutable(model, target, emit);
  ruleViews(model, target, emit);
  rulePolicyWithoutRls(model, target, emit);
  ruleStorageObjects(model, target, emit);
  ruleSensitiveColumns(model, target, emit);
}
