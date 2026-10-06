import { promises as fs } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { UsageError } from "../../../src/cli/args.js";
import { CONFIG_FILE, loadConfig, parseConfig } from "../../../src/cli/config.js";
import { makeTempDir } from "../../helpers/sample-apps.js";

describe("parseConfig", () => {
  it("accepts a full valid config", () => {
    const cfg = parseConfig(
      JSON.stringify({
        failOn: "medium",
        ignorePaths: ["docs/", "**/*.fixture.ts"],
        rules: { "DB-001": "off", "WEB-*": "low", "sec-0*": "critical" },
        baseline: ".whsquad/baseline.json",
      }),
      CONFIG_FILE,
    );
    expect(cfg.failOn).toBe("medium");
    expect(cfg.ignorePaths).toEqual(["docs/", "**/*.fixture.ts"]);
    expect(cfg.rules).toEqual({ "DB-001": "off", "WEB-*": "low", "SEC-0*": "critical" });
    expect(cfg.baseline).toBe(".whsquad/baseline.json");
  });

  it("accepts an empty object", () => {
    expect(parseConfig("{}", CONFIG_FILE)).toEqual({ ignorePaths: [], rules: {} });
  });

  it.each([
    ["not json", "{nope"],
    ["an array", "[]"],
    ["null", "null"],
    ["an unknown key (typo guard)", JSON.stringify({ failon: "high" })],
    ["a bad failOn", JSON.stringify({ failOn: "urgent" })],
    ["ignorePaths that is not an array", JSON.stringify({ ignorePaths: "docs/" })],
    ["a non-string ignorePaths entry", JSON.stringify({ ignorePaths: [1] })],
    ["an empty ignorePaths entry", JSON.stringify({ ignorePaths: [""] })],
    ["an oversized glob", JSON.stringify({ ignorePaths: ["a".repeat(300)] })],
    ["rules that is an array", JSON.stringify({ rules: ["DB-001"] })],
    ["a bad rule value", JSON.stringify({ rules: { "DB-001": "ignore" } })],
    ["a bad rule key", JSON.stringify({ rules: { "db001": "off" } })],
    ["a non-string baseline", JSON.stringify({ baseline: 3 })],
  ])("rejects %s with a UsageError naming the file", (_label, text) => {
    expect(() => parseConfig(text, "cfg/whsquad.config.json")).toThrow(UsageError);
    expect(() => parseConfig(text, "cfg/whsquad.config.json")).toThrow(/whsquad\.config\.json/);
  });
});

describe("loadConfig", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTempDir();
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("returns null when there is no config file", async () => {
    expect(await loadConfig(dir)).toBeNull();
  });

  it("loads the file and resolves the baseline relative to the config directory", async () => {
    await fs.writeFile(path.join(dir, CONFIG_FILE), JSON.stringify({ failOn: "low", baseline: "base.json" }));
    const cfg = await loadConfig(dir);
    expect(cfg?.failOn).toBe("low");
    expect(cfg?.baselinePath).toBe(path.join(dir, "base.json"));
    expect(cfg?.source).toBe(path.join(dir, CONFIG_FILE));
  });

  it("throws a UsageError for an invalid file", async () => {
    await fs.writeFile(path.join(dir, CONFIG_FILE), "{broken");
    await expect(loadConfig(dir)).rejects.toThrow(UsageError);
  });
});
