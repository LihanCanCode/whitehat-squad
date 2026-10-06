import type { Finding } from "../../core/types.js";
import { splitArgs } from "../../core/source/index.js";
import type { Span } from "../../core/source/index.js";
import { describeOrigin, flowOf, unitCode } from "./flow.js";
import { OWASP, bareOf, codeOf, definitionsOf, emit, findCalls, isDirectRef, replaceInLine } from "./shared.js";
import type { FileCtx } from "./shared.js";

const MONGO_IMPORT = /["'](?:mongoose|mongodb|@typegoose\/typegoose|mongoose-[\w-]+)["']/;
const QUERY_CALL =
  /(?<![\w$])(?<recv>[\w$]+(?:\s*\(\s*[^()]*\))?)\s*\.\s*(?<m>find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|replaceOne|deleteOne|deleteMany|countDocuments|exists)\s*\(/;

interface Hit {
  readonly span: Span;
  /** Replacement text for the fix. */
  readonly wrapped: string;
}

/** Tainted values used directly as filter values (not coerced, not wrapped in an operator). */
function directValues(ctx: FileCtx, filter: Span, isTaintedExpr: (bare: string) => boolean, depth = 0): Hit[] {
  const bare = bareOf(ctx, filter);
  if (!/^[{[]/.test(bare) || depth > 2) return [];
  const out: Hit[] = [];
  for (const prop of splitArgs(ctx.src, filter.start + 1, filter.end - 1)) {
    let text = bareOf(ctx, prop);
    let value: Span = prop;
    const keyMatch = /^(?:\.\.\.|(?:[\w$]+|"[^"]*"|'[^']*'|\[[^\]]*\])\s*:\s*)/.exec(text);
    if (keyMatch) value = { start: prop.start + keyMatch[0].length, end: prop.end };
    if (/^\$eq\s*:/.test(text)) continue;
    text = bareOf(ctx, value).trim();
    if (/^[{[]/.test(text)) {
      out.push(...directValues(ctx, value, isTaintedExpr, depth + 1));
    } else if (isDirectRef(text) && isTaintedExpr(text)) {
      out.push({ span: value, wrapped: `String(${codeOf(ctx, value)})` });
    }
  }
  return out;
}

export function nosqlFindings(ctx: FileCtx): Finding[] {
  if (ctx.isClient || ctx.project.sanitizesMongo || !MONGO_IMPORT.test(ctx.src.raw)) return [];
  const findings: Finding[] = [];
  for (const call of findCalls(ctx, QUERY_CALL)) {
    const arg = call.args[0];
    if (!arg) continue;
    const recv = call.match.groups?.recv ?? "";
    const method = call.match.groups?.m ?? "find";
    const modelLike = /^[A-Z]/.test(recv) || /^(?:collection|db|\w*Model|\w*Collection)\b/.test(recv) || /\(/.test(recv);
    const unit = ctx.unitAt(call.open);
    const taint = ctx.taintFor(unit);
    const at = call.open;
    const isTaintedExpr = (b: string): boolean => taint.isTainted(b, at);
    const argBare = bareOf(ctx, arg);
    let hits: Hit[];
    if (/^[{[]/.test(argBare)) {
      hits = directValues(ctx, arg, isTaintedExpr);
    } else if (modelLike && isDirectRef(argBare) && isTaintedExpr(argBare)) {
      // The whole filter is a request object, unless it was built from a literal that only holds safe pieces.
      const defs = definitionsOf(ctx, unit, argBare, at);
      const built = defs.find((d) => /^[{[]/.test(bareOf(ctx, d)));
      hits = built ? directValues(ctx, built, isTaintedExpr) : [{ span: arg, wrapped: `{ ...${codeOf(ctx, arg)} }` }];
      if (built && hits.length === 0) continue;
    } else {
      continue;
    }
    if (hits.length === 0) continue;
    const code = unitCode(ctx, unit);
    const names = hits.flatMap((h) => [...codeOf(ctx, h.span).matchAll(/[A-Za-z_$][\w$]*/g)].map((m) => m[0]));
    const typeChecked = names.some((n) => new RegExp(`typeof\\s+(?:[\\w$.]+\\.)?${n}\\s*(?:===|!==|==|!=)\\s*["']string["']|Array\\.isArray\\(\\s*${n}\\s*\\)`).test(code));
    if (typeChecked) continue;
    const first = hits[0] as Hit;
    const flowCheck = flowOf(ctx, unit, taint, first.span, at);
    if (flowCheck.checked) continue;
    const origin = describeOrigin(taint, [{ kind: "expr", text: codeOf(ctx, first.span), bare: bareOf(ctx, first.span), start: first.span.start }], at);
    const after = replaceInLine(ctx, first.span, first.wrapped);
    findings.push(
      emit(ctx, {
        ruleId: "INJ-008",
        offset: call.index,
        title: "MongoDB filter uses a request value without forcing it to a string (operator injection)",
        severity: "high",
        explanation:
          `A value from ${origin} is used as-is in the filter passed to ${method}(). If the client sends JSON like {"email": {"$ne": null}} (or ?email[$ne]= in a query string), ` +
          "the value is an operator object, not text, and the query matches every document. That turns a login check into 'first user whose password is not null', " +
          "so an attacker signs in as someone else without a password, or reads and deletes other users' records.",
        summary: "Coerce request values to the type you expect (String(x), or schema validation) before putting them in a filter.",
        ...(after ? { after } : {}),
        config:
          "// validate the shape first\nconst { email, password } = loginSchema.parse(await req.json()); // zod: z.object({ email: z.string(), password: z.string() })\nawait User.findOne({ email });\n" +
          "// or force the type\nawait User.findOne({ email: String(req.body.email) });\n// or neutralize operators globally (Express)\napp.use(mongoSanitize());",
        prompt:
          `${method}() filters on a value from ${origin} that is not coerced. Validate the body with a zod schema (strings only) or wrap each filter value in String(), and keep the query otherwise unchanged. Consider mongoose's sanitizeFilter: true.`,
        references: [OWASP.injection, "https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf", "https://mongoosejs.com/docs/6.x/docs/api.html#mongoose_Mongoose-sanitizeFilter"],
        cwe: "CWE-943",
      }),
    );
  }
  return findings;
}
