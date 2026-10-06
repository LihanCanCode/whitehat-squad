import type { Finding } from "../../core/types.js";
import { describeOrigin, flowOf, hasLiteralText } from "./flow.js";
import { OWASP, bareOf, codeOf, definitionsOf, emit, findCalls } from "./shared.js";
import type { FileCtx, Piece } from "./shared.js";
import type { FunctionUnit } from "../../core/source/index.js";

const FILTER_CALL_DOT = /\.\s*(?<m>or|filter|textSearch)\s*\(/;
const STRIPS_SEPARATORS = /\.\s*replace(?:All)?\s*\(\s*(?:\/[^/\n]*[,()][^/\n]*\/|["'][,()]["'])/;

function stripsSeparators(ctx: FileCtx, unit: FunctionUnit, p: Piece, at: number): boolean {
  if (STRIPS_SEPARATORS.test(p.text)) return true;
  if (!/^[A-Za-z_$][\w$]*$/.test(p.bare)) return false;
  return definitionsOf(ctx, unit, p.bare, at).some((d) => STRIPS_SEPARATORS.test(codeOf(ctx, d)));
}

/** INJ-003: request data inside a PostgREST filter string (supabase-js .or/.filter/.textSearch). */
export function postgrestFindings(ctx: FileCtx): Finding[] {
  if (!/supabase/i.test(ctx.src.raw)) return [];
  const findings: Finding[] = [];
  const seen = new Set<number>();
  for (const call of findCalls(ctx, FILTER_CALL_DOT)) {
    const method = call.match.groups?.m ?? "or";
    const unit = ctx.unitAt(call.open);
    const taint = ctx.taintFor(unit);
    for (const arg of call.args) {
      const bare = bareOf(ctx, arg);
      if (/^[[{(]/.test(bare) || bare.includes("=>")) continue;
      const flow = flowOf(ctx, unit, taint, arg, call.open, { sanitized: stripsSeparators });
      const composed = hasLiteralText(flow.pieces) || (method === "or" && flow.tainted.length > 0);
      if (flow.tainted.length === 0 || !composed || seen.has(call.index)) continue;
      seen.add(call.index);
      const origin = describeOrigin(taint, flow.tainted, call.open);
      findings.push(
        emit(ctx, {
          ruleId: "INJ-003",
          offset: call.index,
          title: "Request data is placed inside a Supabase (PostgREST) filter string",
          severity: "medium",
          confidence: hasLiteralText(flow.pieces) ? "high" : "medium",
          explanation:
            `A value from ${origin} is concatenated into the filter string given to .${method}(). PostgREST filter strings use commas, dots and parentheses as syntax, ` +
            "so a visitor can type text like  x,user_id.neq.0  and add their own conditions or widen the query. Row Level Security still applies, but the visitor " +
            "can reach rows the page was never meant to show them (other statuses, hidden or soft-deleted rows) and break the intended filtering.",
          summary: "Pass values through the typed filter helpers, or strip filter syntax from the value before building the string.",
          config:
            "// typed helpers escape the value for you\nawait supabase.from(\"items\").select().ilike(\"name\", `%${q}%`);\n" +
            "// when .or() is unavoidable, remove the characters that are filter syntax\nconst safe = q.replace(/[,()\"\\\\]/g, \"\");\nawait supabase.from(\"items\").select().or(`name.ilike.%${safe}%,description.ilike.%${safe}%`);",
          prompt:
            `request data (${origin}) is interpolated into a Supabase .${method}() filter string. Replace it with typed filters (.ilike, .eq, .in) or strip , ( ) " and backslashes from the value first. Keep the query's behaviour otherwise.`,
          references: [OWASP.injection, "https://supabase.com/docs/reference/javascript/using-filters", "https://postgrest.org/en/stable/references/api/tables_views.html#logical-operators"],
          cwe: "CWE-943",
        }),
      );
    }
  }
  return findings;
}
