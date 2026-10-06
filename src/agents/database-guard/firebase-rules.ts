import { lineOf, makeFinding } from "../../core/finding.js";
import type { Finding } from "../../core/types.js";
import { AGENT_ID, firebaseFix } from "./fixes.js";
import { firebaseAuthOnlyFix } from "./fixes-extra.js";
import { enclosingMatchPaths, isWildcardPath } from "./firebase-scope.js";

export type FirebaseKind = "firestore" | "storage" | "rtdb";

const WRITE_OPS = /\b(write|create|update|delete)\b/i;
const TEST_MODE_DATE = /request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/;
const AUTH_ONLY = /^\(*\s*request\.auth\s*!=\s*null\s*\)*$/;

export function firebaseKind(path: string): FirebaseKind | null {
  const base = path.split("/").pop() ?? "";
  if (base === "firestore.rules") return "firestore";
  if (base === "storage.rules") return "storage";
  if (base === "database.rules.json") return "rtdb";
  return null;
}

/** Blanks // and block comments, keeping offsets and newlines stable for line numbers. */
function blankComments(src: string): string {
  const blank = (m: string): string => m.replace(/[^\n]/g, " ");
  return src.replace(/\/\*[\s\S]*?(\*\/|$)/g, blank).replace(/\/\/[^\n]*/g, blank);
}

const pad2 = (n: string): string => n.padStart(2, "0");

interface Hit {
  readonly index: number;
  readonly snippet: string;
  readonly write: boolean;
  readonly reason: "open" | "expiry" | "authOnly";
  readonly date?: string;
  /** Expiry instant in epoch ms (test-mode rules only). */
  readonly expiresAt?: number;
}

function scanFirestoreLike(clean: string, raw: string): Hit[] {
  const hits: Hit[] = [];
  const scope = enclosingMatchPaths(clean);
  // Bounded quantifiers: rules files are attacker-controlled and an unbounded lazy match is O(n^2).
  const re = /\ballow\s+([a-z ,\t\r\n]{1,80}?)\s*(?::\s*if\s+([^;]{1,2000}?)\s*)?;/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean))) {
    const ops = m[1] ?? "";
    const cond = (m[2] ?? "").trim();
    const snippet = raw.slice(m.index, m.index + m[0].length).replace(/\s+/g, " ").slice(0, 200);
    const write = WRITE_OPS.test(ops);
    if (m[2] === undefined || /^\(*\s*true\s*\)*$/i.test(cond)) {
      hits.push({ index: m.index, snippet, write, reason: "open" });
      continue;
    }
    if (AUTH_ONLY.test(cond)) {
      if (isWildcardPath(scope(m.index))) hits.push({ index: m.index, snippet, write, reason: "authOnly" });
      continue;
    }
    const d = TEST_MODE_DATE.exec(cond);
    if (d && !/&&|\|\|/.test(cond)) {
      const [y, mo, day] = [Number(d[1]), Number(d[2]), Number(d[3])];
      hits.push({
        index: m.index, snippet, write, reason: "expiry", expiresAt: Date.UTC(y, mo - 1, day),
        date: `${d[1]}-${pad2(d[2] as string)}-${pad2(d[3] as string)}`,
      });
    }
  }
  return hits;
}

function scanRtdb(clean: string, raw: string): Hit[] {
  const hits: Hit[] = [];
  const re = /"\.(read|write)"\s*:\s*(true|"\s*true\s*"|"\s*now\s*<\s*(\d{10,})\s*")/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean))) {
    const write = m[1] === "write";
    const snippet = raw.slice(m.index, m.index + m[0].length).slice(0, 200);
    if (m[3]) {
      const date = new Date(Number(m[3]));
      hits.push({
        index: m.index, snippet, write, reason: "expiry", expiresAt: date.getTime(),
        ...(Number.isNaN(date.getTime()) ? {} : { date: date.toISOString().slice(0, 10) }),
      });
    } else hits.push({ index: m.index, snippet, write, reason: "open" });
  }
  return hits;
}

/** RTDB `".read"/".write": "auth != null"` at the root or under a `$wildcard` node. Walks the JSON token stream so paths are exact. */
function scanRtdbAuthOnly(raw: string): Hit[] {
  const hits: Hit[] = [];
  const re = /"((?:[^"\\\n]|\\.)*)"|[{}[\],]/g;
  const stack: string[] = [];
  let pending: { key: string; index: number } | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const tok = m[0];
    if (tok === "{") {
      stack.push(pending?.key ?? "");
      pending = null;
    } else if (tok === "}") stack.pop();
    else if (tok === ",") pending = null;
    else if (tok.startsWith('"')) {
      const isKey = /^\s*:/.test(raw.slice(m.index + tok.length, m.index + tok.length + 40));
      if (isKey) {
        pending = { key: m[1] ?? "", index: m.index };
        continue;
      }
      if (!pending || !/^\.(read|write)$/.test(pending.key)) continue;
      if (m[1]?.replace(/[\s()]/g, "") !== "auth!=null") continue;
      const nodes = stack.slice(stack[1] === "rules" ? 2 : 1);
      if (nodes.length === 0 || nodes.some((k) => k.startsWith("$"))) {
        hits.push({
          index: pending.index, snippet: raw.slice(pending.index, m.index + tok.length).replace(/\s+/g, " ").slice(0, 200),
          write: pending.key === ".write", reason: "authOnly",
        });
      }
      pending = null;
    }
  }
  return hits;
}

const WHERE = { firestore: "Firestore database", storage: "Cloud Storage bucket", rtdb: "Realtime Database" } as const;

function authOnlyFinding(kind: FirebaseKind, file: string, raw: string, hit: Hit, target: string): Finding {
  const where = WHERE[kind];
  const rule = kind === "rtdb" ? "auth != null" : "request.auth != null";
  return makeFinding({
    ruleId: "DB-022", agentId: AGENT_ID, target, severity: "high", cwe: "CWE-285",
    title: `${where} rules only require sign-in for ${hit.write ? "read/write" : "read"} on a wildcard path`,
    explanation: `This rule allows anyone with ${rule} ${hit.write ? "to read and change" : "to read"} every document that matches a wildcard path in your ${where}. Sign-up is public, so "logged in" means "anyone": an attacker registers a free account and then reads${hit.write ? " and overwrites" : ""} all of your users' data. The rule must also compare the user to the data owner (request.auth.uid).`,
    evidence: [{ file, line: lineOf(raw, hit.index), snippet: hit.snippet }],
    fix: firebaseAuthOnlyFix(kind),
  });
}

function toFinding(kind: FirebaseKind, file: string, raw: string, hit: Hit, target: string, now: Date): Finding {
  if (hit.reason === "authOnly") return authOnlyFinding(kind, file, raw, hit, target);
  const where = WHERE[kind];
  const expired = hit.reason === "expiry" && hit.expiresAt !== undefined && hit.expiresAt <= now.getTime();
  const severity = expired ? "medium" : hit.write || hit.reason === "expiry" ? "critical" : "high";
  const access = hit.write ? "read, change and delete everything" : "read everything";
  let explanation: string;
  if (hit.reason === "open") {
    explanation = `This rule lets anyone on the internet, signed in or not, ${access} in your ${where}. Firebase config keys are public in every web app, so no hacking skills are needed: your users' data can be downloaded with a few lines of code.`;
  } else if (expired) {
    explanation = `This Firebase "test mode" rule expired on ${hit.date ?? "an earlier date"}: the database is closed now, but ${hit.write ? "writes" : "reads"} were open until then and the rule will likely be reopened. The usual panic fix when the app breaks is to extend the date or switch to "if true", which leaves your ${where} exposed again. Replace it with real ownership rules now.`;
  } else {
    explanation = `This is Firebase "test mode": it keeps your ${where} wide open until ${hit.date ?? "an expiry date"}. Until then anyone can ${access}. It is also a ticking bomb: when the date passes, the app breaks, and the usual panic fix is to extend the date or switch to "if true", which leaves the data exposed.`;
  }
  return makeFinding({
    ruleId: kind === "storage" ? "DB-011" : "DB-010",
    agentId: AGENT_ID, target, severity, cwe: "CWE-284",
    title: hit.reason === "open"
      ? `${where} rules allow public ${hit.write ? "read/write" : "read"} access`
      : expired
        ? `${where} test-mode rules expired on ${hit.date ?? "an earlier date"}`
        : `${where} rules are in test mode (expires ${hit.date ?? "soon"})`,
    explanation,
    evidence: [{ file, line: lineOf(raw, hit.index), snippet: hit.snippet }],
    fix: firebaseFix(kind),
  });
}

/** `now` is injectable so expiry logic is testable; callers pass the real date. */
export function analyzeFirebaseRules(file: string, raw: string, target: string, now: Date, kindOverride?: FirebaseKind): Finding[] {
  const kind = kindOverride ?? firebaseKind(file);
  if (!kind) return [];
  const clean = kind === "rtdb" ? raw : blankComments(raw);
  const hits = kind === "rtdb" ? [...scanRtdb(clean, raw), ...scanRtdbAuthOnly(raw)] : scanFirestoreLike(clean, raw);
  return hits.map((h) => toFinding(kind, file, raw, h, target, now));
}
