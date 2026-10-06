import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/injection-hunter/index.js";
import { RULES } from "../../../src/agents/injection-hunter/rules.meta.js";
import { express, only, scan } from "./helpers.js";

describe("injection-hunter catalog and agent", () => {
  it("catalogs INJ-001..010 with CWE and OWASP, all static", () => {
    expect(RULES.map((r) => r.id)).toEqual(Array.from({ length: 10 }, (_, i) => `INJ-${String(i + 1).padStart(3, "0")}`));
    for (const r of RULES) {
      expect(r.agent).toBe("injection-hunter");
      expect(r.cwe, r.id).toMatch(/^CWE-\d+$/);
      expect(r.owasp, r.id).toMatch(/^A(?:01|03|10)$/);
      expect(r.modes).toEqual(["static"]);
    }
  });
  it("keeps the squad identity", () => {
    expect(agent).toMatchObject({ id: "injection-hunter", name: "InjectionHunter", modes: ["static"] });
  });
  it("returns nothing for a clean project and dedupes one finding per rule and line", async () => {
    expect(await scan({ "a.js": "export const x = 1;\n" })).toEqual([]);
    const code = express("  exec(`a ${req.body.x}`); exec(`b ${req.body.y}`);", 'const { exec } = require("child_process");');
    expect(only(await scan({ "s.js": code }), "INJ-004")).toHaveLength(1);
  });
});
