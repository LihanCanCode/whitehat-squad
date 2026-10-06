import { makeFinding } from "../../core/finding.js";
import type { Finding } from "../../core/types.js";
import {
  AGENT_ID, dropPolicyFix, enableRlsFix, privateBucketFix, revokeAnonFix, searchPathFix, qtable,
} from "./fixes.js";
import { publicBucketConfigFix } from "./fixes-extra.js";
import type { PolicyInfo, SqlModel, TableInfo } from "./sql-model.js";
import { analyzeSupabase, isSignedInOnly, signedInOnlyFinding } from "./sql-rules-supabase.js";
import { IDENTITY_FN, OPEN_ROLES, displayFn, ev, isTrivialTrue, ownerOf } from "./sql-util.js";

/** Whole words of a table name (split on _ or -) that mark user data; plural forms are accepted. */
const USER_DATA_WORDS = new Set(
  "user profile account member customer order message chat payment invoice subscription booking note document address session token email contact person comment post todo task file upload photo log".split(" "),
);
const UPLOAD_BUCKET = /avatar|upload|user|photo|image|picture|attachment|document|file|media|profile|private|receipt|resume|cv/i;
const ASSET_BUCKET = /^(public|static|assets?|site|marketing|brand|logos?|web)$/i;

type Emit = (f: Finding) => void;

export function isUserDataName(name: string): boolean {
  return name.toLowerCase().split(/[_\-\s]+/).some((w) => USER_DATA_WORDS.has(w) || USER_DATA_WORDS.has(w.replace(/e?s$/, "")) || USER_DATA_WORDS.has(w.replace(/s$/, "")));
}

/** Columns that are private by nature: an open read policy on a table with one of these stays high. */
const PRIVATE_COLUMN = /(?:^|_)(?:e?mail|phone|mobile|address|password|passwd|secret|token|ssn|dob|birth\w*|salary|iban|card|stripe_customer\w*|customer_id|ip_address|location|lat|lng|latitude|longitude)(?:_|$)/i;

function looksLikeUserData(t: TableInfo): boolean {
  return ownerOf(t) !== undefined || isUserDataName(t.name);
}

function ruleNoRls(t: TableInfo, target: string, emit: Emit): void {
  const q = qtable(t.schema, t.name);
  emit(makeFinding({
    ruleId: "DB-001", agentId: AGENT_ID, target, severity: "critical", cwe: "CWE-862",
    title: `Table ${q} has no Row Level Security`,
    explanation: `The table ${q} is created in the public schema but Row Level Security is never enabled. Supabase exposes every public table through its REST API, and the anon key ships in your frontend, so anyone on the internet can read, change or delete every row in this table, for example download all of your users' data.`,
    evidence: ev(t),
    fix: enableRlsFix(t.schema, t.name, ownerOf(t)),
  }));
}

function ruleNoPolicies(t: TableInfo, target: string, emit: Emit): void {
  const q = qtable(t.schema, t.name);
  emit(makeFinding({
    ruleId: "DB-002", agentId: AGENT_ID, target, severity: "low", confidence: "medium", cwe: "CWE-284",
    title: `Table ${q} has RLS enabled but no policies`,
    explanation: `RLS is on for ${q} but no policy exists, so nobody except the service role can read or write it. Either the setup is unfinished (your app will see empty results or errors) or someone may later "fix" it with a wide-open policy. Add explicit, owner-scoped policies.`,
    evidence: ev(t),
    fix: enableRlsFix(t.schema, t.name, ownerOf(t)),
  }));
}

/** SELECT policies like USING (sharing <> 'private') or USING (is_public) filter on the row itself: deliberate sharing. */
function filtersOnRowColumn(expr: string, t: TableInfo, owner: string): boolean {
  const words = new Set(expr.toLowerCase().match(/[a-z_][a-z0-9_]*/g) ?? []);
  return [...t.columns].some((c) => c.toLowerCase() !== owner.toLowerCase() && words.has(c.toLowerCase()));
}

function rulePolicy(p: PolicyInfo, t: TableInfo | undefined, target: string, emit: Emit): void {
  if (!t || p.restrictive || p.roles.every((r) => r === "service_role")) return;
  const owner = ownerOf(t);
  const q = qtable(t.schema, t.name);
  const open = (isTrivialTrue(p.using) || isTrivialTrue(p.check)) && p.roles.some((r) => OPEN_ROLES.has(r));
  if (open && looksLikeUserData(t)) {
    // Calibrated on public repos: read-only open policies are often deliberate (published posts, a
    // catalog). Writes, and reads of tables with private-looking columns, stay high.
    const privateCols = [...t.columns].filter((c) => PRIVATE_COLUMN.test(c));
    const readOnly = p.command === "select";
    const publicRead = readOnly && privateCols.length === 0;
    emit(makeFinding({
      ruleId: "DB-003", agentId: AGENT_ID, target, severity: publicRead ? "medium" : "high", ...(publicRead ? { confidence: "medium" as const } : {}), cwe: "CWE-862",
      title: `Policy "${p.name}" on ${q} allows everyone`,
      explanation: `The policy "${p.name}" uses USING (true) / WITH CHECK (true) for ${p.roles.join(", ")}, so it matches every row. Anyone ${p.roles.includes("authenticated") && p.roles.length === 1 ? "with a free account" : "on the internet"} can ${readOnly ? "read" : "read or modify"} every user's rows in ${q}.` +
        (publicRead
          ? " That is fine if every row and column here is meant to be public (published posts, a product catalog); if any row is private, scope the policy."
          : privateCols.length > 0 ? ` It exposes ${privateCols.slice(0, 4).join(", ")}.` : ""),
      evidence: ev(p),
      fix: dropPolicyFix(p.name, t.schema, t.name, owner, `Replace the open policy on ${q} with an ownership check`),
    }));
    return;
  }
  if (owner && isSignedInOnly(p)) {
    emit(signedInOnlyFinding(p, t, owner, target));
    return;
  }
  const expr = `${p.using ?? ""} ${p.check ?? ""}`;
  const sharing = p.command === "select" && owner !== undefined && filtersOnRowColumn(expr, t, owner);
  if (owner && !open && !sharing && (p.using !== null || p.check !== null) && !IDENTITY_FN.test(expr)) {
    emit(makeFinding({
      ruleId: "DB-004", agentId: AGENT_ID, target, severity: "medium", confidence: "medium", cwe: "CWE-284",
      title: `Policy "${p.name}" on ${q} never checks who the user is`,
      explanation: `${q} has an owner column (${owner}) but the policy "${p.name}" never references auth.uid(), so it cannot tell users apart. Any signed-in user may be able to read or change other users' rows.`,
      evidence: ev(p),
      fix: dropPolicyFix(p.name, t.schema, t.name, owner, `Scope the policy on ${q} to auth.uid() = ${owner}`),
    }));
  }
}

function ruleDefiner(model: SqlModel, target: string, emit: Emit): void {
  for (const fn of model.functions.values()) {
    if (!fn.securityDefiner || fn.hasSearchPath) continue;
    const name = displayFn(fn);
    emit(makeFinding({
      ruleId: "DB-005", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-269",
      title: `SECURITY DEFINER function ${name} has no fixed search_path`,
      explanation: `The function ${name} runs with its owner's (often admin) privileges but does not pin search_path. A user who can create objects in a schema earlier on the path can shadow tables or functions it calls and escalate their privileges.`,
      evidence: ev(fn),
      fix: searchPathFix(fn.name, fn.schema, fn.args),
    }));
  }
}

function ruleGrants(model: SqlModel, target: string, emit: Emit): void {
  const seen = new Set<string>();
  for (const g of model.grants) {
    const key = `${g.file}:${g.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    emit(makeFinding({
      ruleId: "DB-006", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-284",
      title: "Write privileges granted to the anon role",
      explanation: "This statement grants write access (ALL/INSERT/UPDATE/DELETE) on tables to the anon role, which is used by anyone holding your public key. If RLS is missing or loose, anyone on the internet can insert, change or wipe data.",
      evidence: ev(g),
      fix: revokeAnonFix(),
    }));
  }
}

function ruleBuckets(model: SqlModel, target: string, emit: Emit): void {
  for (const b of model.buckets.values()) {
    if (!b.isPublic || (ASSET_BUCKET.test(b.name) && !UPLOAD_BUCKET.test(b.name))) continue;
    const uploads = UPLOAD_BUCKET.test(b.name);
    const base = privateBucketFix(b.name);
    emit(makeFinding({
      ruleId: "DB-007", agentId: AGENT_ID, target, severity: "medium", confidence: uploads ? "high" : "low", cwe: "CWE-284",
      title: `Storage bucket "${b.name}" is public`,
      explanation: `The bucket "${b.name}" is public, so every file in it can be downloaded by anyone who has or guesses the URL, with no login. That is fine for logos, but not for user uploads such as avatars, documents or receipts.`,
      evidence: ev(b),
      fix: b.source === "config" ? publicBucketConfigFix(b.name, base) : base,
    }));
  }
}

export function analyzeSql(model: SqlModel, target: string): Finding[] {
  const out: Finding[] = [];
  const emit: Emit = (f) => out.push(f);
  const policyTables = new Set(model.policies.map((p) => p.tableKey));
  for (const t of model.tables.values()) {
    if (t.schema !== "public") continue;
    if (!t.rlsEnabled) ruleNoRls(t, target, emit);
    else if (!policyTables.has(`${t.schema}.${t.name}`)) ruleNoPolicies(t, target, emit);
  }
  for (const p of model.policies) rulePolicy(p, model.tables.get(p.tableKey), target, emit);
  ruleDefiner(model, target, emit);
  ruleGrants(model, target, emit);
  ruleBuckets(model, target, emit);
  analyzeSupabase(model, target, emit);
  return out;
}
