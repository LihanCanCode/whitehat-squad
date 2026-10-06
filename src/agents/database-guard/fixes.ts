import type { Fix } from "../../core/types.js";

export const AGENT_ID = "database-guard";

export const REFS = {
  rls: "https://supabase.com/docs/guides/database/postgres/row-level-security",
  secdef: "https://supabase.com/docs/guides/database/functions#security-definer-vs-invoker",
  storage: "https://supabase.com/docs/guides/storage/security/access-control",
  grants: "https://supabase.com/docs/guides/database/postgres/roles",
  apiSecurity: "https://supabase.com/docs/guides/api/securing-your-api",
  firestore: "https://firebase.google.com/docs/firestore/security/get-started",
  storageRules: "https://firebase.google.com/docs/storage/security",
  rtdb: "https://firebase.google.com/docs/database/security",
  rulesConditions: "https://firebase.google.com/docs/firestore/security/rules-conditions",
  lint0002: "https://supabase.com/docs/guides/database/database-linter?lint=0002_auth_users_exposed",
  lint0007: "https://supabase.com/docs/guides/database/database-linter?lint=0007_policy_exists_rls_disabled",
  lint0010: "https://supabase.com/docs/guides/database/database-linter?lint=0010_security_definer_view",
  lint0015: "https://supabase.com/docs/guides/database/database-linter?lint=0015_rls_references_user_metadata",
  lint0023: "https://supabase.com/docs/guides/database/database-linter?lint=0023_sensitive_columns_exposed",
  lint0025: "https://supabase.com/docs/guides/database/database-linter?lint=0025_public_bucket_allows_listing",
  lint0028: "https://supabase.com/docs/guides/database/database-linter?lint=0028_anon_security_definer_function_executable",
  lint0029: "https://supabase.com/docs/guides/database/database-linter?lint=0029_authenticated_security_definer_function_executable",
  edgeAuth: "https://supabase.com/docs/guides/functions/auth",
  anonAuth: "https://supabase.com/docs/guides/auth/auth-anonymous",
  cliConfig: "https://supabase.com/docs/guides/local-development/cli/config",
} as const;

/** Double-quotes an identifier only when it needs it. */
export function qid(name: string): string {
  return /^[a-z_][a-z0-9_]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

export function qtable(schema: string, name: string): string {
  return `${qid(schema)}.${qid(name)}`;
}

const OWNER_COLUMN = /^(user_?id|uid|owner(_id|_uuid)?|profile_id|created_by|creator_id|author_id|account_id|tenant_id|org_id|member_id)$/;

/** Column that ties a row to a user. `id` counts only when the table's id references auth.users (the profiles pattern). */
export function ownerColumn(columns: Iterable<string>, opts: { idIsAuthUser?: boolean } = {}): string | undefined {
  let hasId = false;
  for (const c of columns) {
    if (OWNER_COLUMN.test(c)) return c;
    if (c === "id") hasId = true;
  }
  return opts.idIsAuthUser && hasId ? "id" : undefined;
}

export function ownerPolicySql(schema: string, table: string, owner: string | undefined): string {
  const t = qtable(schema, table);
  if (!owner) {
    return `-- Add an owner column first, then restrict access to it:\n-- ALTER TABLE ${t} ADD COLUMN user_id uuid REFERENCES auth.users(id) DEFAULT auth.uid();\n-- CREATE POLICY "Owners only" ON ${t} FOR ALL TO authenticated USING ((select auth.uid()) = user_id) WITH CHECK ((select auth.uid()) = user_id);`;
  }
  const o = qid(owner);
  return `CREATE POLICY "Owners can read own rows" ON ${t} FOR SELECT TO authenticated USING ((select auth.uid()) = ${o});\nCREATE POLICY "Owners can insert own rows" ON ${t} FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) = ${o});\nCREATE POLICY "Owners can update own rows" ON ${t} FOR UPDATE TO authenticated USING ((select auth.uid()) = ${o}) WITH CHECK ((select auth.uid()) = ${o});\nCREATE POLICY "Owners can delete own rows" ON ${t} FOR DELETE TO authenticated USING ((select auth.uid()) = ${o});`;
}

export function enableRlsFix(schema: string, table: string, owner: string | undefined): Fix {
  const t = qtable(schema, table);
  const sql = `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;\n${ownerPolicySql(schema, table, owner)}`;
  return {
    summary: `Enable Row Level Security on ${t} and add an ownership policy`,
    sql,
    agentPrompt: `In my Supabase project, the table ${t} has Row Level Security disabled, so anyone with the public anon key can read and write it. Add a new migration under supabase/migrations/ that enables RLS on ${t} and adds policies so users can only access rows they own (auth.uid() = ${owner ?? "user_id"}). Do not use USING (true). Use this SQL as the starting point:\n\n${sql}`,
    references: [REFS.rls, REFS.apiSecurity],
  };
}

export function dropPolicyFix(policy: string, schema: string, table: string, owner: string | undefined, summary: string): Fix {
  const t = qtable(schema, table);
  const sql = `DROP POLICY IF EXISTS "${policy.replace(/"/g, '""')}" ON ${t};\n${ownerPolicySql(schema, table, owner)}`;
  return {
    summary,
    sql,
    agentPrompt: `In my Supabase project the policy "${policy}" on ${t} lets anyone read or write rows that belong to other users. Write a new migration that drops it and replaces it with policies scoped to the signed-in user via auth.uid(). Never use USING (true) or WITH CHECK (true) on tables with user data. Starting point:\n\n${sql}`,
    references: [REFS.rls],
  };
}

export function searchPathFix(fn: string, schema = "public", args = ""): Fix {
  const q = `${qid(schema)}.${qid(fn)}`;
  const sql = `ALTER FUNCTION ${q}(${args}) SET search_path = '';\n-- If you recreate it, add the clause to the definition:\n-- CREATE OR REPLACE FUNCTION ${q}(...) ... SECURITY DEFINER SET search_path = '' AS $$ ... $$;\n-- and schema-qualify every table inside the body (public.profiles, not profiles).`;
  return {
    summary: `Pin search_path on SECURITY DEFINER function ${fn}`,
    sql,
    agentPrompt: `The SECURITY DEFINER function ${fn} in my Supabase migrations has no SET search_path, so an attacker who can create objects in a schema on the path can hijack it and run code with the function owner's privileges. Add SET search_path = '' to the function (via a new migration) and schema-qualify every object it references. Starting point:\n\n${sql}`,
    references: [REFS.secdef],
  };
}

export function revokeAnonFix(): Fix {
  const sql = `REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM anon;\nALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM anon;\n-- Then grant only what is needed, per table, behind RLS policies.`;
  return {
    summary: "Revoke write privileges from the anon role",
    sql,
    agentPrompt: `A Supabase migration grants write privileges (ALL/INSERT/UPDATE/DELETE) on tables to the anon role, which anyone on the internet can use. Replace it with a migration that revokes those grants from anon and relies on RLS policies for authenticated users. Starting point:\n\n${sql}`,
    references: [REFS.grants, REFS.rls],
  };
}

export function privateBucketFix(bucket: string): Fix {
  const b = bucket.replace(/'/g, "''");
  const sql = `UPDATE storage.buckets SET public = false WHERE id = '${b}';\nCREATE POLICY "Users read own files" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = '${b}' AND (select auth.uid())::text = (storage.foldername(name))[1]);\nCREATE POLICY "Users upload own files" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = '${b}' AND (select auth.uid())::text = (storage.foldername(name))[1]);`;
  return {
    summary: `Make storage bucket ${bucket} private and scope access per user`,
    sql,
    agentPrompt: `My Supabase storage bucket "${bucket}" is public, so every uploaded file is downloadable by anyone who knows or guesses the URL. If it holds user uploads, make it private, store files under a <user id>/ folder prefix, and serve them with signed URLs. Starting point:\n\n${sql}`,
    references: [REFS.storage],
  };
}

export const FIRESTORE_SAFE = `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId}/{document=**} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}`;

export function firebaseFix(kind: "firestore" | "storage" | "rtdb"): Fix {
  if (kind === "rtdb") {
    const config = `{\n  "rules": {\n    "users": {\n      "$uid": {\n        ".read": "auth != null && auth.uid === $uid",\n        ".write": "auth != null && auth.uid === $uid"\n      }\n    }\n  }\n}`;
    return {
      summary: "Restrict Realtime Database rules to the signed-in owner",
      config,
      agentPrompt: `My database.rules.json lets anyone read or write the whole Realtime Database. Rewrite it so every path requires auth != null and, for user data, auth.uid === $uid. Remove any ".read": true / ".write": true and any "now < ..." test-mode expiry. Starting point:\n\n${config}`,
      references: [REFS.rtdb],
    };
  }
  if (kind === "storage") {
    const config = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /users/{userId}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}`;
    return {
      summary: "Restrict Cloud Storage rules to the signed-in owner",
      config,
      agentPrompt: `My storage.rules lets anyone read or write every file in my Firebase Storage bucket. Rewrite the rules so only authenticated users can access files under their own users/<uid>/ folder, and remove "if true" and any request.time test-mode expiry. Starting point:\n\n${config}`,
      references: [REFS.storageRules],
    };
  }
  return {
    summary: "Restrict Firestore rules to the signed-in owner",
    config: FIRESTORE_SAFE,
    agentPrompt: `My firestore.rules lets anyone read or write my whole Firestore database ("if true" or a request.time test-mode expiry). Rewrite the rules so each collection requires request.auth != null and, for user data, request.auth.uid == userId. Deploy with "firebase deploy --only firestore:rules". Starting point:\n\n${FIRESTORE_SAFE}`,
    references: [REFS.firestore],
  };
}
