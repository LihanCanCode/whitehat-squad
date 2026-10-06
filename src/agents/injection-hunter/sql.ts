import type { Finding } from "../../core/types.js";
import { describeOrigin, flowOf, hasLiteralText } from "./flow.js";
import { OWASP, bareOf, codeOf, emit, findCalls, parsePieces } from "./shared.js";
import type { Call, FileCtx, Piece } from "./shared.js";

const DB_RECEIVER =
  /^(?:db|database|pool|client|conn|connection|con|cnx|sql|pg|mysql|mysql2|sqlite|sequelize|knex|kx|trx|tx|transaction|dataSource|manager|queryRunner|entityManager|em|ds|AppDataSource|\w*(?:Pool|Client|Db|DB|Database|Connection|Conn|Sequelize|Knex))$/;
/** Receivers whose single argument is plainly SQL, so a lone tainted value is already dangerous. */
const STRICT_RECEIVER = /^(?:db|database|pool|conn|connection|con|sql|pg|mysql|mysql2|sqlite|sequelize|knex|trx|tx|dataSource|queryRunner|manager)$/;
const SQL_WORD = /\b(?:select|insert|update|delete|with|create|drop|alter|pragma|from|where)\b/i;

const METHOD_CALL = /(?<![\w$])(?<recv>[\w$]+)\s*\.\s*(?<m>query|execute|prepare|exec|run|all|get|each)\s*\(/;
const RAW_CALL = /(?<![\w$])(?<recv>[\w$]+)\s*\.\s*raw\s*\(/;
const BUILDER_RAW = /\.\s*(?:where|orWhere|andWhere|having|orHaving|order|orderBy|group|groupBy|join|select|from)Raw\s*\(/;
const SQL_TAG_FN = /(?<![\w$])sql\s*\.\s*(?:raw|unsafe)\s*\(/;
const PRISMA_UNSAFE = /\.\s*\$(?:query|execute)RawUnsafe\s*\(/;

const TAGGED = /^[\w$.]+\s*`/;
/** Statements run by scripts and seeders are not request-reachable; the untainted rule skips them. */
const SCRIPT_PATH = /(?:^|\/)(?:scripts?|seeds?|seeders?|migrations?|bin|tools|prisma\/seed)(?:\/|\.)/i;

interface SqlSink {
  readonly call: Call;
  readonly kind: "method" | "raw" | "builder" | "sqlfn" | "prisma";
  readonly name: string;
  readonly strict: boolean;
}

function sinksOf(ctx: FileCtx): SqlSink[] {
  const out: SqlSink[] = [];
  for (const call of findCalls(ctx, METHOD_CALL)) {
    const recv = call.match.groups?.recv ?? "";
    const m = call.match.groups?.m ?? "";
    if (!DB_RECEIVER.test(recv)) continue;
    out.push({ call, kind: "method", name: m, strict: STRICT_RECEIVER.test(recv) });
  }
  for (const call of findCalls(ctx, RAW_CALL)) {
    const recv = call.match.groups?.recv ?? "";
    if (recv === "String" || !DB_RECEIVER.test(recv)) continue;
    out.push({ call, kind: "raw", name: "raw", strict: true });
  }
  for (const call of findCalls(ctx, BUILDER_RAW)) out.push({ call, kind: "builder", name: "whereRaw", strict: true });
  for (const call of findCalls(ctx, SQL_TAG_FN)) out.push({ call, kind: "sqlfn", name: "sql.raw", strict: true });
  for (const call of findCalls(ctx, PRISMA_UNSAFE)) out.push({ call, kind: "prisma", name: "$queryRawUnsafe", strict: true });
  return out;
}

const TITLE = "SQL query is built from request data";

/** Build a parameterized version of a one-line template/concatenation query, when it is simple enough. */
function parameterized(ctx: FileCtx, sink: SqlSink, taintedStarts: ReadonlySet<number>): string | undefined {
  const { call } = sink;
  const arg = call.args[0];
  if (call.args.length !== 1 || !arg) return undefined;
  const pieces = parsePieces(ctx.src, arg);
  if (!hasLiteralText(pieces)) return undefined;
  const positional = sink.kind === "method" && sink.name === "query";
  const values: string[] = [];
  let text = "";
  let hasExpr = false;
  let dropQuote = "";
  for (const p of pieces) {
    if (p.kind === "lit") {
      const lit = dropQuote && p.text.startsWith(dropQuote) ? p.text.slice(1) : p.text;
      dropQuote = "";
      text += lit;
    } else if (taintedStarts.has(p.start)) {
      values.push(p.text);
      const prev = text.slice(-1);
      if (prev === "'" || prev === '"') {
        text = text.slice(0, -1);
        dropQuote = prev;
      }
      text += positional ? `$${values.length}` : "?";
    } else {
      hasExpr = true;
      dropQuote = "";
      text += `\${${p.text}}`;
    }
  }
  const quoted = hasExpr || text.includes("\n") ? `\`${text.replace(/`/g, "\\`")}\`` : JSON.stringify(text);
  const head = codeOf(ctx, { start: call.index, end: call.open + 1 });
  return `${head}${quoted}, [${values.join(", ")}])`;
}

export function sqlFindings(ctx: FileCtx): Finding[] {
  const findings: Finding[] = [];
  if (ctx.isClient) return findings;
  for (const sink of sinksOf(ctx)) {
    const arg = sink.call.args[0];
    if (!arg) continue;
    const argBare = bareOf(ctx, arg);
    if (TAGGED.test(argBare) || argBare.startsWith("{")) continue;
    const unit = ctx.unitAt(sink.call.open);
    const taint = ctx.taintFor(unit);
    const at = sink.call.open;
    const flow = flowOf(ctx, unit, taint, arg, at);
    const literal = flow.pieces.filter((p) => p.kind === "lit").map((p) => p.text).join(" ");
    if (sink.kind === "method" && ["run", "all", "get", "each"].includes(sink.name) && !SQL_WORD.test(literal)) continue;
    const loneOk = sink.strict;

    if (flow.tainted.length > 0 && (loneOk || hasLiteralText(flow.pieces))) {
      const origin = describeOrigin(taint, flow.tainted, at);
      const after = parameterized(ctx, sink, new Set(flow.tainted.map((p) => p.start)));
      findings.push(
        emit(ctx, {
          ruleId: "INJ-001",
          offset: sink.call.index,
          title: sink.kind === "prisma" ? `${TITLE} and passed to ${sink.name}` : TITLE,
          severity: "critical",
          explanation:
            `A value from ${origin} is placed straight into the SQL text passed to ${sink.call.match[0].replace(/\s*\($/, "").trim()}(). ` +
            "Anyone who can call this endpoint can type their own SQL (for example ' OR 1=1 -- or a UNION SELECT) and read, change or delete any table the database user can reach, " +
            "including other people's rows and password hashes. Placeholders keep the data out of the SQL grammar; string building does not.",
          summary: "Send the SQL text as a constant and pass request values as bound parameters.",
          ...(after ? { after } : {}),
          config:
            "// pg / mysql2 / sqlite: constant text + values array\nawait pool.query(\"SELECT * FROM items WHERE owner = $1 AND name = $2\", [ownerId, name]);\n" +
            "// Prisma: tagged template (parameterized) instead of $queryRawUnsafe\nawait prisma.$queryRaw`SELECT * FROM items WHERE name = ${name}`;\n" +
            "// Column / table names cannot be parameters: map a fixed key to a constant\nconst ORDER = { name: \"name\", date: \"created_at\" } as const;\nconst col = ORDER[sort as keyof typeof ORDER] ?? \"created_at\";",
          prompt:
            `the SQL passed to ${sink.call.match[0].replace(/\s*\($/, "").trim()}() is built from ${origin}. Rewrite it as constant SQL with bound parameters ($1/? placeholders and a values array, or a tagged template such as prisma.$queryRaw\`...\`). ` +
            "Column and table names must come from a fixed allowlist object, never from the request. Do not change the query's behaviour otherwise.",
          references: [OWASP.sql, "https://owasp.org/www-community/attacks/SQL_Injection"],
          cwe: "CWE-89",
        }),
      );
      continue;
    }

    if (sink.kind === "prisma" && !SCRIPT_PATH.test(ctx.path) && !flow.checked && isNonLiteral(flow.pieces)) {
      findings.push(
        emit(ctx, {
          ruleId: "INJ-002",
          offset: sink.call.index,
          title: "Prisma unsafe raw query takes a non-literal query string",
          severity: "high",
          confidence: "medium",
          explanation:
            `${sink.name}() runs whatever string it is given, with no escaping. The query here is assembled at runtime rather than written as a fixed string, ` +
            "so one future change that lets user text reach it (a search box, a sort column, a tenant name) becomes a full SQL injection. " +
            "The scanner could not see request data reaching it today, so check where the pieces come from.",
          summary: "Use the parameterized tagged-template form, or keep the SQL literal and pass values as arguments.",
          config:
            "await prisma.$queryRaw`SELECT * FROM items WHERE name = ${name}`;\n// or keep the text constant and bind the values\nawait prisma.$queryRawUnsafe(\"SELECT * FROM items WHERE name = $1\", name);",
          prompt: `${sink.name}() receives a query string built at runtime. Convert it to prisma.$queryRaw tagged-template form, or a literal string with $1.. placeholders and the values passed as extra arguments. Identifiers must come from an allowlist.`,
          references: [OWASP.sql, "https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/raw-queries#sql-injection"],
          cwe: "CWE-89",
        }),
      );
    }
  }
  return findings;
}

/** True when the string contains something other than literal text and constants. */
function isNonLiteral(pieces: readonly Piece[]): boolean {
  return pieces.some((p) => p.kind === "expr" && !/^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)*$/.test(p.bare.trim()) && !/^["'`][^"'`$]*["'`]$/.test(p.bare.trim()));
}
