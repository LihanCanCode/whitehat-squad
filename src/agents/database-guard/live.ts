import { makeFinding } from "../../core/finding.js";
import { getLiveAssets } from "../../core/live-assets.js";
import type { Finding, ScanContext } from "../../core/types.js";
import { AGENT_ID, REFS, enableRlsFix } from "./fixes.js";

export const MAX_PROBES = 20;
const MAX_BYTES = 65_536;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{15,25})\.supabase\.co/;
const JWT_RE = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}/g;
const SRC_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte)$/i;
const MAX_SOURCE_FILES = 300;

interface Corpus {
  readonly texts: readonly string[];
}

async function gatherTexts(ctx: ScanContext): Promise<Corpus> {
  const texts: string[] = [];
  try {
    const assets = await getLiveAssets(ctx);
    if (assets.html) texts.push(assets.html.body);
    for (const s of assets.scripts) texts.push(s.body);
  } catch {
    /* live assets are best effort */
  }
  const paths = ctx.files.paths.filter((p) => SRC_FILE.test(p) && !p.includes("node_modules")).slice(0, MAX_SOURCE_FILES);
  for (const p of paths) {
    const body = await ctx.files.read(p);
    if (body) texts.push(body);
  }
  return { texts };
}

function anonRole(jwt: string): boolean {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as { role?: unknown };
    return payload.role === "anon";
  } catch {
    return false;
  }
}

function findAnonKey(texts: readonly string[]): string | undefined {
  for (const t of texts) for (const m of t.matchAll(JWT_RE)) if (anonRole(m[0])) return m[0];
  return undefined;
}

function collectNames(texts: readonly string[], re: RegExp): string[] {
  const names = new Set<string>();
  for (const t of texts) {
    for (const m of t.matchAll(re)) {
      const n = m[1];
      if (n && NAME_RE.test(n)) names.add(n);
      if (names.size >= MAX_PROBES) return [...names];
    }
  }
  return [...names];
}

const SB_FROM = /(?<!Array|storage|Buffer|Observable|Object)\.from\(\s*["'`]([^"'`]+)["'`]\s*\)/g;
const FS_COLLECTION = /\bcollection\(\s*(?:[A-Za-z_$][\w$.]*\s*,\s*)?["'`]([^"'`/]+)["'`]/g;

function failed(status: number): boolean {
  return status !== 200;
}

function keysOfFirstRow(body: string): { columns: string[]; parsed: boolean } {
  try {
    const data: unknown = JSON.parse(body);
    const row = Array.isArray(data) ? data[0] : undefined;
    if (row && typeof row === "object") return { columns: Object.keys(row as object).slice(0, 40), parsed: true };
    return { columns: [], parsed: true };
  } catch {
    return { columns: [], parsed: false };
  }
}

async function probeSupabase(
  ctx: ScanContext, base: string, anon: string, tables: readonly string[], target: string,
): Promise<Finding[]> {
  const out: Finding[] = [];
  const http = ctx.http;
  if (!http) return out;
  for (const table of tables) {
    const url = `${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
    try {
      const res = await http.get(url, { headers: { apikey: anon, Authorization: `Bearer ${anon}` }, maxBytes: MAX_BYTES });
      if (failed(res.status)) continue;
      const { columns, parsed } = keysOfFirstRow(res.body);
      const hasRow = parsed ? columns.length > 0 : res.body.trimStart().startsWith("[{");
      if (!hasRow) continue;
      const cols = columns.length ? `columns: ${columns.join(", ")}` : "columns: (unreadable)";
      out.push(makeFinding({
        ruleId: "DB-L01", agentId: AGENT_ID, target, severity: "critical", cwe: "CWE-862",
        title: `Table "${table}" is readable by anyone with the public key`,
        explanation: `Anyone on the internet can read the table "${table}" using only the public anon key that ships in your website. A single read-only request returned at least one row, so an attacker can download this whole table, for example every user's records. (Only the table name and column names were recorded, never the data.)`,
        evidence: [{ url: `${base}/rest/v1/${table}?select=*&limit=1`, snippet: `GET /rest/v1/${table} -> HTTP ${res.status}, rows: 1, ${cols}`.slice(0, 200) }],
        fix: { ...enableRlsFix("public", table, undefined), references: [REFS.rls, REFS.apiSecurity] },
      }));
    } catch {
      /* network errors are not findings */
    }
  }
  return out;
}

async function probeFirestore(ctx: ScanContext, projectId: string, collections: readonly string[], target: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const http = ctx.http;
  if (!http) return out;
  for (const name of collections) {
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${encodeURIComponent(name)}?pageSize=1`;
    try {
      const res = await http.get(url, { maxBytes: MAX_BYTES });
      if (failed(res.status)) continue;
      const data = JSON.parse(res.body) as { documents?: { fields?: Record<string, unknown> }[] };
      const doc = data.documents?.[0];
      if (!doc) continue;
      const fields = Object.keys(doc.fields ?? {}).slice(0, 40);
      out.push(makeFinding({
        ruleId: "DB-L02", agentId: AGENT_ID, target, severity: "critical", cwe: "CWE-284",
        title: `Firestore collection "${name}" is readable by anyone`,
        explanation: `Anyone on the internet can read the Firestore collection "${name}" without signing in. A read-only request returned a document, so an attacker can download the whole collection. (Only the collection and field names were recorded, never the data.)`,
        evidence: [{ url: `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${name}`, snippet: `GET documents/${name} -> HTTP ${res.status}, documents: 1, fields: ${fields.join(", ") || "(none)"}`.slice(0, 200) }],
        fix: {
          summary: `Require sign-in and ownership for the "${name}" collection`,
          config: "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /" + name + "/{docId} {\n      allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;\n    }\n  }\n}",
          agentPrompt: `My Firestore collection "${name}" can be read by anonymous visitors. Update firestore.rules so access requires request.auth != null and ownership (request.auth.uid == resource.data.userId), then deploy with "firebase deploy --only firestore:rules".`,
          references: [REFS.firestore],
        },
      }));
    } catch {
      /* permission denied / network / malformed JSON: not a finding */
    }
  }
  return out;
}

export async function runLiveProbes(ctx: ScanContext, target: string): Promise<Finding[]> {
  if (ctx.mode !== "live" || !ctx.http || !ctx.options.probeBackend) return [];
  const { texts } = await gatherTexts(ctx);
  const out: Finding[] = [];

  const base = ctx.stack.supabaseUrl ?? texts.map((t) => SUPABASE_URL_RE.exec(t)?.[0]).find(Boolean);
  const anon = ctx.stack.anonKey ?? findAnonKey(texts);
  if (base && anon) {
    ctx.registerSecret(anon);
    const tables = collectNames(texts, SB_FROM);
    out.push(...(await probeSupabase(ctx, base.replace(/\/+$/, ""), anon, tables, target)));
  }

  const projectId = ctx.stack.firebaseProjectId ?? texts.map((t) => /projectId\s*[:=]\s*["']([a-z][a-z0-9-]{3,29})["']/.exec(t)?.[1]).find(Boolean);
  if (projectId) out.push(...(await probeFirestore(ctx, projectId, collectNames(texts, FS_COLLECTION), target)));
  return out;
}
