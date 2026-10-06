import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ALL_RULES, ruleHelpUri } from "../../src/rules/catalog.js";
import { renderRulesDoc } from "../../src/rules/render-docs.js";

const doc = readFileSync(new URL("../../docs/rules.md", import.meta.url), "utf8").replace(/\r\n/g, "\n");

describe("docs/rules.md", () => {
  it("matches the catalog (regenerate with: npx tsx scripts/gen-rules.ts)", () => {
    expect(doc).toBe(renderRulesDoc(ALL_RULES));
  });

  it("has a heading for every helpUri anchor", () => {
    for (const r of ALL_RULES) {
      const anchor = ruleHelpUri(r.id).split("#")[1];
      expect(anchor).toBe(r.id.toLowerCase());
      expect(doc).toContain(`\n### ${r.id}\n`);
    }
  });

  it("escapes pipes in table titles", () => {
    const out = renderRulesDoc([{ ...ALL_RULES[0]!, title: "a | b" }]);
    expect(out).toContain("a \\| b");
  });
});
