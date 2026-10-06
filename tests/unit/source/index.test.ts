import { describe, expect, it } from "vitest";
import * as engine from "../../../src/core/source/index.js";
import { analyzeTaint, createSource, handlerUnits, lineOf, matchClose, snippetAt, unitBody, unitHas } from "../../../src/core/source/index.js";

describe("index", () => {
  it("re-exports the documented API", () => {
    for (const name of [
      "createSource", "lineOf", "lineText", "snippetAt", "matchClose", "matchOpen", "exprEnd", "splitArgs",
      "parseBindingNames", "parseParams", "classifyFile", "fileDirectives", "isTestPath", "isGeneratedPath", "isVendorPath",
      "routeFromPath", "findUnits", "handlerUnits", "unitAt", "unitBody", "findRouteRegistrations", "analyzeTaint",
      "REQUEST_SOURCES", "DEFAULT_SANITIZERS", "unitHas", "guardMatches", "AUTH_CHECK", "RATE_LIMIT", "OWNERSHIP",
      "SIGNATURE_CHECK", "VALIDATION", "GUARDS",
    ]) {
      expect(engine, name).toHaveProperty(name);
    }
  });

  it("README worked example: SQL sink rule across two Express routes without taint leakage", () => {
    const SQL_SINK = /\b(?:db|pool|client|prisma)\s*\.\s*(?:query|\$queryRawUnsafe|execute)\s*\(/g;
    const raw = [
      "const app = express();",
      "app.get('/a', requireAuth, async (req, res) => {",
      "  const { id } = req.params;",
      "  await db.query(`select * from t where id = ${id}`);",
      "});",
      "app.get('/b', async (req, res) => {",
      "  const n = Number(req.query.n);",
      "  await db.query(`select * from t where id = ${n}`);",
      "  await db.query(`select * from t where id = ${id}`);",
      "  // db.query(`${req.body.x}`)",
      "});",
    ].join("\n");
    const src = createSource("server.js", raw);
    const findings: Array<{ line: number; snippet: string; severity: string }> = [];
    for (const unit of handlerUnits(src)) {
      const taint = analyzeTaint(src, unit);
      for (const m of unitBody(src, unit).bare.matchAll(SQL_SINK)) {
        const open = unit.start + m.index + m[0].length - 1;
        const close = matchClose(src, open);
        if (!taint.isTainted(src.code.slice(open + 1, close - 1), open)) continue;
        findings.push({ line: lineOf(src, open), snippet: snippetAt(src, open), severity: unitHas(src, unit, "auth") ? "medium" : "high" });
      }
    }
    expect(findings).toEqual([{ line: 4, snippet: "await db.query(`select * from t where id = ${id}`);", severity: "medium" }]);
  });
});
