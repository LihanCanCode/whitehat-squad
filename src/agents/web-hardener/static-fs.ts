import { analyzeTaint, exprEnd, findUnits, matchClose, parseParams, splitArgs } from "../../core/source/index.js";
import type { FunctionUnit, TaintAnalysis } from "../../core/source/index.js";
import { skipWs } from "../../core/source/scan.js";
import type { Finding } from "../../core/types.js";
import { make } from "./fixes.js";
import { bareMatches, lineAt, scopeOf, snippetOf } from "./util.js";
import type { WebFile } from "./util.js";

// A .replace() only counts as sanitizing when it strips ".." (traversal segments); stripping whitespace
// or other characters (e.g. .replace(/\s/g, '_')) leaves "../" untouched.
const SANITIZES_PATH = /path\.basename\(|\.replace\([^)]*\\\.\\\.[^)]*\)|\bsanitiz|\buuid\(|randomUUID\(|\bnanoid\(/i;

const WRITE_FNS = "writeFile(?:Sync)?|createWriteStream|rename(?:Sync)?|copyFile(?:Sync)?|cp(?:Sync)?|appendFile(?:Sync)?";
const FS_RECEIVER = new RegExp(String.raw`\b(?:fs|fsp|fsPromises|promises)\s*(?:\.\s*promises\s*)?\.\s*(?:${WRITE_FNS})\s*\(`, "g");
const BARE_WRITE = new RegExp(String.raw`(?<![.\w$])(${WRITE_FNS})\s*\(`, "g");
const FS_MODULE = String.raw`["'](?:node:)?fs(?:/promises)?["']`;
const IDENT = /(?<![\w$.])[A-Za-z_$][\w$]*/g;
const escapeRe = (s: string): string => s.replace(/[$]/g, (c) => `\\${c}`);

function importedFromFs(file: WebFile, name: string): boolean {
  const code = file.src.code;
  return (
    new RegExp(String.raw`\{[^}]*\b${name}\b[^}]*\}\s*from\s*${FS_MODULE}`).test(code) ||
    new RegExp(String.raw`\{[^}]*\b${name}\b[^}]*\}\s*=\s*(?:await\s+)?require\(\s*${FS_MODULE}\s*\)`).test(code)
  );
}

/** A bare writeFile( is fs unless the file binds that name from another module or defines it locally. */
function isFsName(file: WebFile, name: string): boolean {
  if (importedFromFs(file, name)) return true;
  const code = file.src.code;
  const elsewhere =
    new RegExp(String.raw`\{[^}]*\b${name}\b[^}]*\}\s*from\s*["'](?!(?:node:)?fs(?:/promises)?["'])`).test(code) ||
    new RegExp(String.raw`\b(?:function|const|let|var)\s+${name}\b`).test(code);
  return !elsewhere;
}

interface WriteCall {
  readonly at: number;
  readonly open: number;
}

function writeCalls(file: WebFile): WriteCall[] {
  const out: WriteCall[] = [];
  for (const m of bareMatches(file.src, FS_RECEIVER)) out.push({ at: m.index, open: m.index + m[0].length - 1 });
  for (const m of bareMatches(file.src, BARE_WRITE)) {
    if (isFsName(file, (m[1] ?? "").replace(/\s+/g, ""))) out.push({ at: m.index, open: m.index + m[0].length - 1 });
  }
  return out;
}

/** The right-hand side of the last write to `name` before `at`. */
export function lastRhs(file: WebFile, name: string, at: number): string | undefined {
  const { src } = file;
  const re = new RegExp(String.raw`(?<![\w$.])${escapeRe(name)}\s*(?::[^=\n;]+)?=(?![=>])`, "g");
  let last: string | undefined;
  for (const m of src.bare.matchAll(re)) {
    if (m.index >= at) break;
    const from = skipWs(src.bare, m.index + m[0].length);
    last = src.code.slice(from, exprEnd(src, from, true));
  }
  return last;
}

/**
 * Request taint for the scope, plus the parameters of local helper functions (const save = async (file) => ...)
 * that the scope calls with tainted arguments, so a write inside the helper is still attributed to the request.
 */
function scopeTaint(file: WebFile, scope: FunctionUnit): TaintAnalysis {
  const { src } = file;
  const base = analyzeTaint(src, scope);
  const extra = new Set<string>();
  const scopeBare = src.bare.slice(scope.start, scope.end);
  for (const u of findUnits(src)) {
    if (u === scope || u.role || u.start < scope.start || u.end > scope.end || u.name === "" || u.name === "default") continue;
    const params = parseParams(u.params);
    const re = new RegExp(String.raw`(?<![\w$.])${escapeRe(u.name)}\s*\(`, "g");
    for (const m of scopeBare.matchAll(re)) {
      const open = scope.start + m.index + m[0].length - 1;
      const close = matchClose(src, open);
      if (close < 0) continue;
      splitArgs(src, open + 1, close - 1).forEach((a, k) => {
        if (base.isTainted(src.code.slice(a.start, a.end), open)) for (const n of params[k]?.names ?? []) extra.add(n);
      });
    }
  }
  return extra.size === 0 ? base : analyzeTaint(src, scope, { taintedNames: [...extra] });
}

export function pathTraversalFindings(file: WebFile, target: string): Finding[] {
  const out: Finding[] = [];
  const { src } = file;
  for (const call of writeCalls(file)) {
    const close = matchClose(src, call.open);
    if (close < 0) continue;
    const args = splitArgs(src, call.open + 1, close - 1).slice(0, 2);
    const scope = scopeOf(file, call.at);
    const taint = scopeTaint(file, scope);
    const tainted = taint.taintedNames(call.at);
    let origin: string | undefined;
    for (const a of args) {
      const code = src.code.slice(a.start, a.end);
      if (SANITIZES_PATH.test(code)) continue;
      const names = [...src.bare.slice(a.start, a.end).matchAll(IDENT)].map((x) => x[0]).filter((n) => tainted.has(n));
      const live = names.filter((n) => !SANITIZES_PATH.test(lastRhs(file, n, call.at) ?? ""));
      if (live.length > 0) origin = taint.originOf(live[0] ?? "", call.at) ?? live[0];
      else if (names.length === 0 && taint.isTainted(code, call.at)) origin = "request data";
      if (origin) break;
    }
    if (!origin) continue;
    const line = lineAt(file, call.at);
    out.push(
      make({
        ruleId: "WEB-006",
        title: "File write uses an attacker-controlled name with no sanitization",
        severity: "high",
        confidence: "medium",
        explanation:
          `The file name written to disk comes from ${origin}, which an attacker controls directly ` +
          "(an uploaded file's own name, or a request field) and is never sanitized. A name like \"../../app/config.js\" " +
          "or one containing a path separator can write outside the intended folder, overwriting other files or planting code.",
        evidence: [{ file: file.path, line, snippet: snippetOf(file, call.at) }],
        fix: {
          summary: "Generate the stored file name yourself (e.g. randomUUID()) and keep the original name only as metadata.",
          config: "import { randomUUID } from 'crypto';\nconst filename = `${randomUUID()}${path.extname(file.name)}`;",
          agentPrompt:
            `In ${file.path} near line ${line}, stop using the uploaded/request-supplied name as the ` +
            "file name on disk. Generate a random name server-side (randomUUID()), keep only a safe extension from the " +
            "original, and store the user's original file name separately as metadata if you need to display it.",
          references: ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
        },
        target,
        cwe: "CWE-22",
      }),
    );
  }
  return out;
}
