/** Backend identifiers that can be recovered from any text (source, .env, or a shipped bundle). */
export interface BackendHints {
  supabaseUrl?: string;
  anonKey?: string;
  firebaseProjectId?: string;
}

const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{12,32})\.supabase\.co/;
const JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g;
const FIREBASE_GATE_RE = /firebase|authDomain|storageBucket/i;
const FIREBASE_PROJECT_ID_RE = /projectId["']?\s*[:=]\s*["']([a-z][a-z0-9-]{3,29})["']/;
const FIREBASE_APP_DOMAIN_RE = /\b([a-z][a-z0-9-]{3,29})\.firebaseapp\.com/;

function jwtRole(token: string): string | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const parsed: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (parsed && typeof parsed === "object" && "role" in parsed) {
      const role = (parsed as { role: unknown }).role;
      return typeof role === "string" ? role : undefined;
    }
  } catch {
    /* not a JWT we can read */
  }
  return undefined;
}

/** Only a JWT whose role is exactly "anon" is accepted; service_role and others never are. */
export function findAnonKey(text: string): string | undefined {
  for (const m of text.matchAll(JWT_RE)) {
    if (jwtRole(m[0]) === "anon") return m[0];
  }
  return undefined;
}

export function extractBackendHints(text: string): BackendHints {
  const out: BackendHints = {};
  const url = SUPABASE_URL_RE.exec(text);
  if (url) out.supabaseUrl = url[0];
  const anon = findAnonKey(text);
  if (anon) out.anonKey = anon;
  if (FIREBASE_GATE_RE.test(text)) {
    const id = FIREBASE_PROJECT_ID_RE.exec(text)?.[1] ?? FIREBASE_APP_DOMAIN_RE.exec(text)?.[1];
    if (id) out.firebaseProjectId = id;
  }
  return out;
}

/** Keeps `base` values and fills only the fields it is missing from `extra`. */
export function mergeHints(base: BackendHints, extra: BackendHints): BackendHints {
  const supabaseUrl = base.supabaseUrl ?? extra.supabaseUrl;
  const anonKey = base.anonKey ?? extra.anonKey;
  const firebaseProjectId = base.firebaseProjectId ?? extra.firebaseProjectId;
  return {
    ...(supabaseUrl ? { supabaseUrl } : {}),
    ...(anonKey ? { anonKey } : {}),
    ...(firebaseProjectId ? { firebaseProjectId } : {}),
  };
}
