import { describe, expect, it } from "vitest";
import { makeFinding } from "../../src/core/finding.js";
import { runScan, shellQuote } from "../../src/core/orchestrator.js";
import type { Agent } from "../../src/core/types.js";
import { memFiles } from "../helpers/memfs.js";

describe("shellQuote", () => {
  it("leaves safe arguments bare on every platform", () => {
    expect(shellQuote("./my-app", "linux")).toBe("./my-app");
    expect(shellQuote("./my-app", "win32")).toBe("./my-app");
  });
  it("uses single quotes on POSIX and escapes embedded single quotes", () => {
    expect(shellQuote("my app", "linux")).toBe("'my app'");
    expect(shellQuote("it's", "darwin")).toBe("'it'\\''s'");
  });
  it("uses double quotes on win32 and escapes embedded double quotes", () => {
    expect(shellQuote("C:\My Projects\app", "win32")).toBe('"C:\My Projects\app"');
    expect(shellQuote('say "hi"', "win32")).toBe('"say \\"hi\\""');
    expect(shellQuote("it's", "win32")).toBe('"it\'s"');
  });
  it("defaults to the host platform", () => {
    expect(shellQuote("a b")).toBe(shellQuote("a b", process.platform));
  });
});

describe("printed verify command", () => {
  const agent: Agent = {
    id: "t", name: "t", role: "r", modes: ["static"],
    run: async () => [
      makeFinding({
        ruleId: "T-001", agentId: "t", title: "t", severity: "high", target: ".", explanation: "e",
        evidence: [{ snippet: "s" }], fix: { summary: "s", agentPrompt: "p", references: [] },
      }),
    ],
  };
  const commandFor = async (platform: NodeJS.Platform, flags: string[] = []): Promise<string> => {
    const report = await runScan({
      mode: "static", targetLabel: "C:\My Projects\app", files: memFiles({}), agents: [agent], platform, verifyFlags: flags,
    });
    return report.findings[0]?.verify.command ?? "";
  };
  it("quotes the target for the shell flavour and appends scan flags", async () => {
    expect(await commandFor("win32")).toBe('whsquad verify T-001 "C:\My Projects\app"');
    expect(await commandFor("linux", ["--git-history"])).toBe("whsquad verify T-001 'C:\My Projects\app' --git-history");
  });
});
