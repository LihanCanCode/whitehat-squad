import type { Finding } from "../../core/types.js";
import { describeOrigin, flowOf, unitCode } from "./flow.js";
import { OWASP, bareOf, codeOf, emit, findCalls, replaceInLine } from "./shared.js";
import type { Call, FileCtx } from "./shared.js";

const FS_METHODS =
  "readFile|readFileSync|createReadStream|readdir|readdirSync|stat|statSync|lstat|lstatSync|access|accessSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|readlink|opendir|opendirSync|rename|renameSync|copyFile|copyFileSync";
const FS_MEMBER = new RegExp(`(?<![\\w$.])(?:fs\\s*\\.\\s*promises|fs|fsp|fse|fsExtra|fsPromises|promises)\\s*\\.\\s*(?:${FS_METHODS})\\s*\\(`);
const FS_BARE = /(?<![\w$.])(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|readdir|readdirSync|unlink|unlinkSync|rmSync)\s*\(/;
const FS_IMPORT = /["'](?:node:)?fs(?:\/promises|-extra)?["']/;
const SEND_FILE = /(?<![\w$])(?:res|reply|response|ctx|c|context)\s*\.\s*(?:sendFile|download|sendfile)\s*\(/;
const DESTRUCTIVE = /(?:unlink|rm|rmdir)(?:Sync)?$/;
const WRITES = /(?:write|append|rename|copy|createWrite)/i;

/** Evidence of containment: a `..` check, or resolve/normalize followed by a prefix check. */
function containmentGuard(code: string): boolean {
  if (/(?:includes|indexOf|startsWith)\(\s*["'`]\.\.["'`]/.test(code)) return true;
  return /\.\s*startsWith\s*\(/.test(code) && /\b(?:resolve|realpath(?:Sync)?|normalize)\s*\(/.test(code);
}

export function pathFindings(ctx: FileCtx): Finding[] {
  if (ctx.isClient) return [];
  const sinks: Call[] = [...findCalls(ctx, FS_MEMBER), ...findCalls(ctx, SEND_FILE)];
  if (FS_IMPORT.test(ctx.src.raw)) sinks.push(...findCalls(ctx, FS_BARE));
  const findings: Finding[] = [];
  for (const call of sinks) {
    const arg = call.args[0];
    if (!arg) continue;
    const name = /([A-Za-z]+)\s*\($/.exec(call.match[0])?.[1] ?? "";
    const options = call.args[1];
    if (/^(?:sendFile|sendfile|download)$/.test(name) && options && /\broot\s*:/.test(codeOf(ctx, options))) continue;
    const unit = ctx.unitAt(call.open);
    const taint = ctx.taintFor(unit);
    const flow = flowOf(ctx, unit, taint, arg, call.open);
    if (flow.tainted.length === 0 || containmentGuard(unitCode(ctx, unit))) continue;
    const origin = describeOrigin(taint, flow.tainted, call.open);
    const destructive = DESTRUCTIVE.test(name);
    const writes = WRITES.test(name);
    const after = replaceInLine(ctx, arg, `path.join(UPLOAD_DIR, path.basename(${bareOf(ctx, arg) === "" ? "name" : codeOf(ctx, arg)}))`);
    findings.push(
      emit(ctx, {
        ruleId: "INJ-007",
        offset: call.index,
        title: destructive ? "File delete path is built from request data (path traversal)" : writes ? "File write path is built from request data (path traversal)" : "File path is built from request data (path traversal)",
        severity: destructive ? "critical" : "high",
        explanation:
          `A file path derived from ${origin} reaches ${name}(). A visitor can send ../../ sequences (or an absolute path) to step out of the intended folder and ` +
          (destructive
            ? "delete any file the server process can remove: uploads, the database file, or application code."
            : writes
              ? "overwrite files elsewhere on the server, such as application code or config, which can lead to code execution."
              : "read files that were never meant to be public: .env, source code, SSH keys and the database file.") +
          " path.join does not prevent this; it happily resolves the .. segments.",
        summary: "Strip the request value down to a file name, join it to a fixed directory, and verify the resolved path stays inside it.",
        ...(after ? { after } : {}),
        config:
          "const BASE = path.resolve(UPLOAD_DIR);\nconst full = path.resolve(BASE, path.basename(name)); // basename drops any directory part\nif (!full.startsWith(BASE + path.sep)) throw new Error(\"invalid path\");\nawait fs.promises.readFile(full);",
        prompt:
          `${name}() receives a path built from ${origin}. Use path.basename() on the request value (or an id looked up in a database), resolve it against a fixed base directory, and reject the request unless the resolved path starts with that base plus path.sep.`,
        references: [OWASP.path, "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/22.html"],
        cwe: "CWE-22",
      }),
    );
  }
  return findings;
}
