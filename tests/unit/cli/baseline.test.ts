import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { UsageError } from "../../../src/cli/args.js";
import { buildBaseline, loadBaselineIds, parseBaseline } from "../../../src/cli/baseline.js";
import { knownFindings } from "../../../src/cli/diff.js";
import { makeTempDir } from "../../helpers/sample-apps.js";
import { sampleFinding, sampleReport } from "../../helpers/sample-report.js";

describe("baseline document", () => {
  it("records ids, rule ids, target and tool version, sorted for stable diffs", () => {
    const doc = buildBaseline(sampleReport({ target: "./app" }));
    expect(doc.target).toBe("./app");
    expect(doc.toolVersion).toBe("0.3.2");
    expect(doc.findings.map((f) => f.id)).toEqual([...doc.findings.map((f) => f.id)].sort());
    expect(doc.findings[0]).toEqual({ id: expect.any(String), ruleId: expect.any(String) });
    expect(doc.findings).toHaveLength(6);
  });

  it("round-trips through parseBaseline", () => {
    const doc = buildBaseline(sampleReport());
    expect(parseBaseline(JSON.stringify(doc), "b.json").ids.size).toBe(6);
  });

  it.each([
    ["not json", "{"],
    ["a missing findings array", JSON.stringify({ tool: "whitehat-squad" })],
    ["a finding without an id", JSON.stringify({ findings: [{ ruleId: "X-1" }] })],
    ["a non-object", "3"],
  ])("rejects %s with a UsageError", (_l, text) => {
    expect(() => parseBaseline(text, "b.json")).toThrow(UsageError);
  });
});

describe("loadBaselineIds", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTempDir();
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("reads a baseline file", async () => {
    const file = path.join(dir, "b.json");
    await fs.writeFile(file, JSON.stringify(buildBaseline(sampleReport())));
    expect((await loadBaselineIds(file)).size).toBe(6);
  });

  it("throws a UsageError for a missing file", async () => {
    await expect(loadBaselineIds(path.join(dir, "nope.json"))).rejects.toThrow(UsageError);
  });
});

describe("knownFindings (diff.ts)", () => {
  it("splits a report into known (in baseline) and new findings by id", () => {
    const a = sampleFinding({ id: "a" });
    const b = sampleFinding({ id: "b" });
    const split = knownFindings(new Set(["a", "gone"]), sampleReport({ findings: [a, b] }));
    expect(split.known.map((f) => f.id)).toEqual(["a"]);
    expect(split.fresh.map((f) => f.id)).toEqual(["b"]);
  });
});
