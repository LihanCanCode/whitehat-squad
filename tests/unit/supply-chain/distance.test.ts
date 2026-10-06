import { describe, expect, it } from "vitest";
import { damerauLevenshtein } from "../../../src/agents/supply-chain/distance.js";

describe("damerauLevenshtein", () => {
  it("is zero for equal strings", () => {
    expect(damerauLevenshtein("react", "react")).toBe(0);
  });
  it("handles empty strings", () => {
    expect(damerauLevenshtein("", "abc")).toBe(3);
    expect(damerauLevenshtein("abc", "")).toBe(3);
    expect(damerauLevenshtein("", "")).toBe(0);
  });
  it("counts substitutions, insertions and deletions", () => {
    expect(damerauLevenshtein("kitten", "sitting")).toBe(3);
    expect(damerauLevenshtein("lodash", "lodas")).toBe(1);
    expect(damerauLevenshtein("express", "expresss")).toBe(1);
    expect(damerauLevenshtein("react", "reakt")).toBe(1);
  });
  it("counts an adjacent transposition as one edit", () => {
    expect(damerauLevenshtein("ab", "ba")).toBe(1);
    expect(damerauLevenshtein("recat", "react")).toBe(1);
    expect(damerauLevenshtein("axios", "aixos")).toBe(1);
  });
  it("is symmetric", () => {
    expect(damerauLevenshtein("openai", "opnai")).toBe(damerauLevenshtein("opnai", "openai"));
  });
  it("stops early when the length gap exceeds the cap", () => {
    expect(damerauLevenshtein("a", "abcdefgh", 2)).toBeGreaterThan(2);
  });
  it("exits early once the cap is certainly exceeded and reports cap + 1", () => {
    expect(damerauLevenshtein("abcdefghij", "klmnopqrst")).toBe(10);
    expect(damerauLevenshtein("abcdefghij", "klmnopqrst", 2)).toBe(3);
    expect(damerauLevenshtein("abcdefghij", "klmnopqrst", 1)).toBe(2);
  });
  it("matches the uncapped distance whenever it is within the cap", () => {
    const words = ["react", "recat", "reakt", "lodash", "lodahs", "expres", "express", "axios", "aixos", "zod", "zodd", "next", "nxet", "vue", "vuex"];
    for (const a of words) {
      for (const b of words) {
        const full = damerauLevenshtein(a, b);
        for (const cap of [0, 1, 2]) {
          expect(damerauLevenshtein(a, b, cap)).toBe(full <= cap ? full : cap + 1);
        }
      }
    }
  });
});
