import { promises as fs } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { claudeArgs, parseClaudeOutput, ProviderError, resolveClaudeExecutable } from "../../../src/review/provider.js";
import { makeTempDir } from "../../helpers/sample-apps.js";

describe("claude CLI arguments are locked down", () => {
  const args = claudeArgs("sonnet", "SYS", { type: "object" });
  it("disables every tool, MCP servers and session persistence", () => {
    expect(args.slice(args.indexOf("--tools"), args.indexOf("--tools") + 2)).toEqual(["--tools", ""]);
    expect(args).toContain("--strict-mcp-config");
    expect(args).toContain("--no-session-persistence");
    expect(args).toContain("-p");
  });
  it("never bypasses permissions and pins our system prompt, model and schema", () => {
    expect(args.join(" ")).not.toMatch(/dangerously|bypass|--add-dir/i);
    expect(args[args.indexOf("--system-prompt") + 1]).toBe("SYS");
    expect(args[args.indexOf("--model") + 1]).toBe("sonnet");
    expect(JSON.parse(args[args.indexOf("--json-schema") + 1] ?? "")).toEqual({ type: "object" });
  });
});

describe("parseClaudeOutput", () => {
  it("returns structured_output and the reported cost", () => {
    expect(parseClaudeOutput(JSON.stringify({ structured_output: { ok: true }, total_cost_usd: 0.04 }))).toEqual({ data: { ok: true }, costUsd: 0.04 });
  });
  it("falls back to a JSON result string", () => {
    expect(parseClaudeOutput(JSON.stringify({ result: '{"a":1}' })).data).toEqual({ a: 1 });
  });
  it("throws on errors, non-JSON output and missing structured data", () => {
    expect(() => parseClaudeOutput(JSON.stringify({ is_error: true, subtype: "error_max_turns" }))).toThrow(ProviderError);
    expect(() => parseClaudeOutput("not json")).toThrow(ProviderError);
    expect(() => parseClaudeOutput(JSON.stringify({ result: "plain text" }))).toThrow(ProviderError);
  });
});

describe("resolveClaudeExecutable", () => {
  it("resolves the Windows npm shim to the real claude.exe (spawned without a shell)", async () => {
    const dir = await makeTempDir();
    try {
      const exe = path.join(dir, "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe");
      await fs.mkdir(path.dirname(exe), { recursive: true });
      await fs.writeFile(exe, "");
      await fs.writeFile(path.join(dir, "claude.cmd"), '@ECHO off\n"%dp0%\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe"   %*\n');
      expect(resolveClaudeExecutable({ PATH: dir }, "win32")).toBe(exe);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
  it("returns undefined when claude is not installed, and ignores relative PATH entries", () => {
    expect(resolveClaudeExecutable({ PATH: `relative${path.delimiter}` }, "win32")).toBeUndefined();
  });
});
