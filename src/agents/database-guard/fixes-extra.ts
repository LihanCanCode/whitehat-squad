import type { Fix } from "../../core/types.js";
import { REFS, ownerPolicySql, qid, qtable } from "./fixes.js";

/** Fix builders for the Supabase-specific rules DB-012..DB-021. */

function fix(summary: string, body: { sql?: string; config?: string }, prompt: string, references: readonly string[]): Fix {
  const code = body.sql ?? body.config ?? "";
  return { summary, ...body, agentPrompt: `${prompt}\n\nStarting point:\n\n${code}`, references };
}

export function userMetadataFix(where: string, kind: "policy" | "function"): Fix {
  const sql = [
    "-- user_metadata can be edited by the signed-in user themself (supabase.auth.updateUser). Never authorize on it.",
    "-- Put authorization data in app_metadata, which only the server / service role can write:",
    "--   UPDATE auth.users SET raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{\"role\": \"admin\"}'::jsonb WHERE id = '<user uuid>';",
    "-- Then read it in the policy / function like this:",
    "--   (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'",
    "-- or look the role up in your own table that users cannot write to:",
    "--   exists (select 1 from public.user_roles r where r.user_id = (select auth.uid()) and r.role = 'admin')",
  ].join("\n");
  return fix(
    `Stop using user_metadata for authorization in ${where}`, { sql },
    `In ${where} my Supabase ${kind} decides access from user_metadata / raw_user_meta_data. Any user can rewrite their own user_metadata, so they can make themselves admin. Rewrite it to use app_metadata (server-controlled) or a roles table, in a new migration.`,
    [REFS.lint0015, REFS.rls],
  );
}

export function escalationFix(schema: string, table: string, protectedCols: readonly string[], safeCols: readonly string[]): Fix {
  const t = qtable(schema, table);
  const grant = safeCols.length > 0
    ? `GRANT UPDATE (${safeCols.map(qid).join(", ")}) ON ${t} TO authenticated;`
    : `-- GRANT UPDATE (<columns users may edit>) ON ${t} TO authenticated;`;
  const sql = `-- Users must not be able to write ${protectedCols.join(", ")} themselves.\nREVOKE UPDATE ON ${t} FROM anon, authenticated;\n${grant}\n-- Change ${protectedCols.join(", ")} only from trusted server code (service role) or a SECURITY DEFINER function.`;
  return fix(
    `Block users from updating ${protectedCols.join(", ")} on ${t}`, { sql },
    `On ${t} the own-row UPDATE policy lets every signed-in user edit their whole row, including ${protectedCols.join(", ")}, so anyone can promote themselves. Add a migration that revokes table-wide UPDATE from anon/authenticated and grants UPDATE only on the columns users should edit.`,
    [REFS.grants, REFS.rls],
  );
}

export function definerExecFix(schema: string, name: string, args: string): Fix {
  const f = `${qid(schema)}.${qid(name)}(${args})`;
  const sql = `REVOKE EXECUTE ON FUNCTION ${f} FROM public, anon, authenticated;\n-- Call it only from trusted server code:\nGRANT EXECUTE ON FUNCTION ${f} TO service_role;\n-- Or keep it callable by signed-in users but check auth.uid() inside the body, and consider moving it to a non-exposed schema.`;
  return fix(
    `Remove public execute access from ${schema}.${name}`, { sql },
    `The SECURITY DEFINER function ${schema}.${name} runs with elevated rights but anon/authenticated can call it through /rest/v1/rpc. Revoke EXECUTE from public, anon and authenticated in a new migration (or add an auth.uid() check inside and move it out of the exposed schema).`,
    [REFS.lint0028, REFS.lint0029, REFS.secdef],
  );
}

export function viewFix(schema: string, name: string, exposesAuthUsers: boolean): Fix {
  const v = qtable(schema, name);
  const sql = `ALTER VIEW ${v} SET (security_invoker = true);\n-- or, if the view must not be reachable through the API at all:\n-- REVOKE SELECT ON ${v} FROM anon, authenticated;${exposesAuthUsers ? "\n-- Do not select from auth.users in a public view: copy only the columns you need into a table with RLS." : ""}`;
  return fix(
    `Make view ${v} respect the caller's Row Level Security`, { sql },
    `The view ${v} runs with its owner's rights and bypasses Row Level Security on the tables it reads. Add a migration that sets security_invoker = true (Postgres 15+) or revokes SELECT from anon and authenticated.`,
    [exposesAuthUsers ? REFS.lint0002 : REFS.lint0010, REFS.rls],
  );
}

export function policyNoRlsFix(schema: string, table: string): Fix {
  const t = qtable(schema, table);
  const sql = `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;`;
  return fix(
    `Enable Row Level Security on ${t} so its policies take effect`, { sql },
    `The table ${t} has policies but Row Level Security is never enabled, so the policies are ignored and the table is open to everyone with the anon key. Add a migration that runs ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY.`,
    [REFS.lint0007, REFS.rls],
  );
}

export function signedInOnlyFix(policy: string, schema: string, table: string, owner: string): Fix {
  const t = qtable(schema, table);
  const sql = `DROP POLICY IF EXISTS "${policy.replace(/"/g, '""')}" ON ${t};\n${ownerPolicySql(schema, table, owner)}`;
  return fix(
    `Scope the policy on ${t} to the row owner (${owner})`, { sql },
    `The policy "${policy}" on ${t} only checks that someone is signed in. Sign-up is open, so anyone can create an account and read or change every user's rows. Replace it with a migration that compares auth.uid() to ${owner}.`,
    [REFS.rls],
  );
}

export function storagePolicyFix(policy: string, listing: boolean): Fix {
  const p = policy.replace(/"/g, '""');
  const sql = listing
    ? `-- Public buckets serve files by URL without any SELECT policy, so this policy only enables listing every file.\nDROP POLICY IF EXISTS "${p}" ON storage.objects;`
    : `DROP POLICY IF EXISTS "${p}" ON storage.objects;\nCREATE POLICY "Users manage own files" ON storage.objects FOR ALL TO authenticated USING (bucket_id = '<bucket>' AND (select auth.uid())::text = (storage.foldername(name))[1]) WITH CHECK (bucket_id = '<bucket>' AND (select auth.uid())::text = (storage.foldername(name))[1]);`;
  return fix(
    listing ? "Drop the policy that lets anyone list a public bucket" : "Scope the storage policy to the uploader's own folder", { sql },
    listing
      ? `The storage policy "${policy}" lets anyone list every file in a public bucket. Drop it in a new migration: public buckets do not need a SELECT policy to serve files by URL.`
      : `The storage policy "${policy}" lets any matching user write or delete files without an ownership check. Replace it so files live under a <user id>/ folder and only that user can modify them.`,
    [REFS.lint0025, REFS.storage],
  );
}

export function sensitiveColumnsFix(schema: string, table: string, sensitive: readonly string[], safe: readonly string[]): Fix {
  const t = qtable(schema, table);
  const sql = `REVOKE SELECT ON ${t} FROM anon, authenticated;\n${safe.length > 0 ? `GRANT SELECT (${safe.map(qid).join(", ")}) ON ${t} TO anon, authenticated;` : `-- GRANT SELECT (<non-secret columns>) ON ${t} TO anon, authenticated;`}\n-- Better: move ${sensitive.join(", ")} into a private table that has no API-readable policy.`;
  return fix(
    `Stop exposing ${sensitive.join(", ")} on ${t}`, { sql },
    `The table ${t} has columns (${sensitive.join(", ")}) that look like secrets, and a policy lets everyone read them. Revoke column access for anon/authenticated or move the secrets to a table only the service role can read, in a new migration.`,
    [REFS.lint0023, REFS.rls],
  );
}

export function verifyJwtFix(fn: string): Fix {
  const config = `[functions.${fn}]\nverify_jwt = true\n# If it must stay public (webhook), verify the caller inside the function:\n#   const event = await stripe.webhooks.constructEventAsync(body, req.headers.get("stripe-signature")!, Deno.env.get("STRIPE_WEBHOOK_SECRET")!)\n#   or: const { data: { user } } = await supabase.auth.getUser(token)`;
  return fix(
    `Require a valid JWT or verify the caller inside ${fn}`, { config },
    `The Supabase Edge Function "${fn}" has verify_jwt = false in supabase/config.toml and its code does not authenticate callers, so anyone on the internet can invoke it. Set verify_jwt = true, or add a signature / auth.getUser() / shared-secret check inside the function.`,
    [REFS.edgeAuth, REFS.cliConfig],
  );
}

export function anonymousFix(table: string, policy: string): Fix {
  const sql = `-- Anonymous sign-ins get the "authenticated" role. Exclude them where it matters:\nDROP POLICY IF EXISTS "${policy.replace(/"/g, '""')}" ON ${table};\nCREATE POLICY "${policy.replace(/"/g, '""')}" ON ${table} AS RESTRICTIVE FOR ALL TO authenticated USING ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);\n-- ...then re-add the permissive policy that grants access (ideally owner-scoped with auth.uid()).`;
  return fix(
    "Keep anonymous users out of authenticated-only policies", { sql },
    `Anonymous sign-ins are enabled, and the "to authenticated" policy "${policy}" does not check is_anonymous, so a visitor who never registered gets the same access as a real user. Add an is_anonymous check (or turn anonymous sign-ins off) in a migration.`,
    [REFS.anonAuth, REFS.rls],
  );
}

export function publicBucketConfigFix(bucket: string, base: Fix): Fix {
  const config = `[storage.buckets.${bucket}]\npublic = false`;
  return { ...base, config, agentPrompt: `${base.agentPrompt}\n\nIn supabase/config.toml set:\n\n${config}`, references: [...base.references, REFS.cliConfig] };
}

export function firebaseAuthOnlyFix(kind: "firestore" | "storage" | "rtdb"): Fix {
  const config = kind === "rtdb"
    ? `{\n  "rules": {\n    "users": {\n      "$uid": {\n        ".read": "auth != null && auth.uid === $uid",\n        ".write": "auth != null && auth.uid === $uid"\n      }\n    }\n  }\n}`
    : kind === "storage"
      ? "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /users/{userId}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}"
      : "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId}/{document=**} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}";
  return fix(
    "Check ownership, not just sign-in", { config },
    "My Firebase rules only require request.auth != null (auth != null for Realtime Database) on a wildcard path. Sign-up is public, so anyone can create an account and read or write everyone's data. Rewrite the rules to compare request.auth.uid with the document owner (path variable or resource.data.userId) and deploy them.",
    [REFS.rulesConditions, kind === "rtdb" ? REFS.rtdb : kind === "storage" ? REFS.storageRules : REFS.firestore],
  );
}
