import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HELP, parseCli, UsageError } from "../../../src/cli/args.js";
import { rootReader, withRemediation } from "../../../src/cli/fix.js";
import { makeTempDir } from "../../helpers/sample-apps.js";
import { finding, reportOf } from "../remediation/builders.js";

describe("parseCli: fix flags", () => {
  it("parses --write and the prompt/triage formats", () => {
    expect(parseCli(["fix", ".", "--write"]).options.write).toBe(true);
    expect(parseCli(["fix", "."]).options.write).toBe(false);
    expect(parseCli(["fix", ".", "--format", "triage"]).options.format).toBe("triage");
    expect(parseCli(["fix", ".", "-f", "prompt"]).options.format).toBe("prompt");
    expect(parseCli(["fix", "app"]).command).toBe("fix");
  });
  it("still rejects unknown formats", () => {
    expect(() => parseCli(["fix", ".", "--format", "yaml"])).toThrow(UsageError);
  });
  it("documents fix in the help", () => {
    for (const w of ["whsquad fix", "--write", "triage", "prompt"]) expect(HELP).toContain(w);
  });
});

describe("withRemediation", () => {
  it("attaches the plan without mutating the original report", () => {
    const report = reportOf([finding({ id: "a", ruleId: "AUTH-002" })]);
    const out = withRemediation(report);
    expect(out.remediation?.steps).toHaveLength(1);
    expect(report.remediation).toBeUndefined();
  });
});

describe("rootReader", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTempDir();
    await fs.writeFile(path.join(dir, "a.ts"), "hello", "utf8");
    await fs.writeFile(path.join(dir, "big.ts"), "x".repeat(1_000_001), "utf8");
    await fs.mkdir(path.join(dir, "sub"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("reads files under the root", async () => {
    expect(await rootReader(dir)("a.ts")).toBe("hello");
  });
  it("returns null for missing, oversized, directory, and out-of-root paths", async () => {
    const read = rootReader(dir);
    expect(await read("missing.ts")).toBeNull();
    expect(await read("big.ts")).toBeNull();
    expect(await read("sub")).toBeNull();
    expect(await read("../outside.ts")).toBeNull();
    expect(await read(path.join(path.dirname(dir), "x.ts"))).toBeNull();
    expect(await read("")).toBeNull();
  });
});
