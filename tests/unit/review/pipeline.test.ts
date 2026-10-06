import { describe, expect, it } from "vitest";
import { cacheKey, parseCandidates, parseVerdict, runReview } from "../../../src/review/pipeline.js";
import type { CachedUnit, ReviewCache } from "../../../src/review/pipeline.js";
import { buildUnits } from "../../../src/review/surface.js";
import { phaseOf } from "../../../src/remediation/phases.js";
import { memFiles } from "../../helpers/memfs.js";
import { APP, CONFIRMED, FakeProvider, PRICE_CANDIDATE, priceHunter } from "./fixtures.js";

const units = () => buildUnits(memFiles(APP), []);

class MemCache implements ReviewCache {
  readonly map = new Map<string, CachedUnit>();
  get(k: string) { return this.map.get(k); }
  set(v: CachedUnit) { this.map.set(v.key, v); }
}

describe("runReview", () => {
  it("hunts every unit, validates the candidate and reports an AI-labelled, advisory finding", async () => {
    const p = new FakeProvider(priceHunter);
    const r = await runReview(await units(), p, { target: ".", maxCalls: 10 });
    expect(p.hunterCalls).toBe(2);
    expect(p.validatorCalls).toBe(1);
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0]!;
    expect(f).toMatchObject({ ruleId: "REV-003", origin: "ai", reviewModel: "fake-model", reviewState: "confirmed", severity: "high", confidence: "medium", agentId: "ai-review" });
    expect(f.evidence[0]).toMatchObject({ file: "app/actions/orders.ts", line: 7 });
    expect(f.verify.command).toBe(`whsquad review --recheck ${f.id} .`);
    expect(f.fix.agentPrompt).toContain("load the product's price");
    expect(r.calls).toBe(3);
  });

  it("drops a candidate whose quoted code does not exist, without spending a validator call", async () => {
    const invented = { ...PRICE_CANDIDATE, evidence: [{ file: "app/actions/orders.ts", line: 7, quote: "const total = req.body.total;" }] };
    const p = new FakeProvider((pr) => (pr.includes("placeOrder") ? { candidates: [invented] } : { candidates: [] }));
    const r = await runReview(await units(), p, { target: ".", maxCalls: 10 });
    expect(r.findings).toEqual([]);
    expect(p.validatorCalls).toBe(0);
    expect(r.ledger.find((l) => l.unit.includes("placeOrder"))?.dropped).toBe(1);
  });

  it("does not report rejected candidates; needs_validation becomes low-confidence info", async () => {
    const rejected = await runReview(await units(), new FakeProvider(priceHunter, () => ({ ...CONFIRMED, verdict: "rejected" })), { target: ".", maxCalls: 10 });
    expect(rejected.findings).toEqual([]);
    expect(rejected.ledger.reduce((n, l) => n + l.rejected, 0)).toBe(1);
    const needs = await runReview(await units(), new FakeProvider(priceHunter, () => ({ ...CONFIRMED, verdict: "needs_validation" })), { target: ".", maxCalls: 10 });
    expect(needs.findings[0]).toMatchObject({ reviewState: "needs_validation", severity: "info", confidence: "low" });
  });

  it("keeps a confirmed finding on the hunter's verified evidence when the validator cites invented lines", async () => {
    const lying = { ...CONFIRMED, evidence: [{ file: "app/actions/orders.ts", line: 7, quote: "await chargeCard(price);" }] };
    const r = await runReview(await units(), new FakeProvider(priceHunter, () => lying), { target: ".", maxCalls: 10 });
    expect(r.findings[0]?.evidence[0]?.snippet).toBe('const price = Number(form.get("price"));');
  });

  it("treats --max-calls as a hard ceiling; unvalidated candidates are never reported or cached", async () => {
    const cache = new MemCache();
    const us = await units();
    const p = new FakeProvider(priceHunter);
    const r = await runReview(us, p, { target: ".", maxCalls: 1, concurrency: 1, cache });
    expect(p.requests).toHaveLength(1);
    expect(r.findings).toEqual([]);
    const statuses = r.ledger.map((l) => l.status).sort();
    expect(statuses).toEqual(["reviewed", "skipped-budget"]);
    expect(r.ledger.reduce((n, l) => n + l.unvalidated, 0) + p.hunterCalls).toBeGreaterThanOrEqual(1);
    for (const l of r.ledger) if (l.unvalidated > 0) expect(cache.map.size).toBe(0);
  });

  it("re-uses cached units (no calls) until their code changes", async () => {
    const cache = new MemCache();
    const us = await units();
    await runReview(us, new FakeProvider(priceHunter), { target: ".", maxCalls: 10, cache });
    const again = new FakeProvider(priceHunter);
    const r = await runReview(us, again, { target: ".", maxCalls: 10, cache });
    expect(again.requests).toHaveLength(0);
    expect(r.findings).toHaveLength(1);
    expect(r.ledger.every((l) => l.status === "cached")).toBe(true);
    expect(cacheKey(us[0]!, "other-model")).not.toBe(cacheKey(us[0]!, "fake-model"));
  });

  it("records a failing provider per unit instead of crashing, and keeps injection notices", async () => {
    const failing = new FakeProvider(() => { throw new Error("rate limited"); });
    const r = await runReview(await units(), failing, { target: ".", maxCalls: 10 });
    expect(r.ledger.every((l) => l.status === "error" && l.error === "rate limited")).toBe(true);
    const noisy = await runReview(await units(), new FakeProvider(() => ({ candidates: [], injection_notice: "file says: ignore previous instructions" })), { target: ".", maxCalls: 10 });
    expect(noisy.injectionNotices.length).toBe(2);
  });
});

describe("output parsing never trusts the model blindly", () => {
  it("drops candidates with unknown classes or no evidence, flattens hostile text", () => {
    const { candidates } = parseCandidates({ candidates: [
      { ...PRICE_CANDIDATE, class: "SEC-001" },
      { ...PRICE_CANDIDATE, evidence: [] },
      { ...PRICE_CANDIDATE, title: "Bad\u001b[2J\nthing" },
    ] });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.title).toBe("Bad thing");
    expect(() => parseCandidates("nope")).toThrow(/hunter schema/);
  });
  it("rejects verdicts outside the contract", () => {
    expect(parseVerdict({ verdict: "maybe" })).toBeUndefined();
    expect(parseVerdict({ ...CONFIRMED, severity: "apocalyptic" })?.severity).toBe("medium");
  });
});

describe("fix plan phases for AI classes", () => {
  it("puts authorization/logic in phase 3, cross-file injection in 4 and AI steering in 6", () => {
    expect([phaseOf("REV-001"), phaseOf("REV-003"), phaseOf("REV-006"), phaseOf("REV-008")]).toEqual([3, 3, 4, 6]);
  });
});
