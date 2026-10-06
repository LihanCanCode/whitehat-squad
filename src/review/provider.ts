import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";

/** One structured request: the model must answer with JSON matching `schema`. */
export interface LlmRequest {
  readonly system: string;
  readonly prompt: string;
  readonly schema: object;
}

export interface LlmResponse {
  readonly data: unknown;
  /** Notional cost reported by the backend (list price; subscription users are not billed per call). */
  readonly costUsd?: number;
}

/** A reasoning backend. Only the Claude Code CLI is implemented; the interface keeps others pluggable. */
export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  complete(request: LlmRequest): Promise<LlmResponse>;
}

export class ProviderError extends Error {}

export interface ClaudeCliOptions {
  readonly model: string;
  /** Empty folder the CLI runs in, so the scanned repo's CLAUDE.md / .claude settings never load. */
  readonly sandboxDir: string;
  readonly timeoutMs?: number;
  /** Executable name or path; defaults to `claude`. */
  readonly command?: string;
}

const DEFAULT_TIMEOUT_MS = 360_000;
const KILL_GRACE_MS = 5_000;
const MAX_OUTPUT = 10_000_000;
const MAX_STDERR = 64_000;

/**
 * The real `claude` executable, so we can spawn it without a shell (cmd.exe would reinterpret the
 * quotes and metacharacters in our system prompt and schema). On Windows npm installs a `claude.cmd`
 * shim that calls `...\bin\claude.exe`; resolve through it. Returns undefined when not found.
 */
export function resolveClaudeExecutable(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  /** The scanned repo: PATH entries inside it (e.g. a committed node_modules/.bin/claude) are never used. */
  untrustedRoot?: string,
): string | undefined {
  const inside = (d: string): boolean => {
    if (!untrustedRoot) return false;
    const rel = path.relative(path.resolve(untrustedRoot), path.resolve(d));
    return rel === "" || (rel.split(path.sep)[0] !== ".." && !path.isAbsolute(rel));
  };
  // npm/npx prepend <cwd>/node_modules/.bin to PATH: a repo could ship its own "claude" there.
  const dirs = (env["PATH"] ?? env["Path"] ?? "")
    .split(path.delimiter)
    .filter((d) => d && path.isAbsolute(d) && !inside(d) && !/[\\/]node_modules[\\/]\.bin[\\/]?$/i.test(d));
  if (platform !== "win32") {
    for (const d of dirs) if (existsSync(path.join(d, "claude"))) return path.join(d, "claude");
    return undefined;
  }
  for (const d of dirs) if (existsSync(path.join(d, "claude.exe"))) return path.join(d, "claude.exe");
  for (const d of dirs) {
    const shim = path.join(d, "claude.cmd");
    if (!existsSync(shim)) continue;
    const m = /"%dp0%\\?([^"]+\.exe)"/i.exec(readFileSync(shim, "utf8"));
    if (m?.[1]) {
      const exe = path.join(d, m[1]);
      if (existsSync(exe)) return exe;
    }
  }
  return undefined;
}

/**
 * Locked-down argv: no tools (no file, shell or web access), no MCP servers, no saved session,
 * our own system prompt, schema-validated JSON output. Exported for tests.
 */
export function claudeArgs(model: string, system: string, schema: object): string[] {
  return [
    "-p",
    "--tools", "",
    "--strict-mcp-config",
    "--no-session-persistence",
    "--output-format", "json",
    "--model", model,
    "--system-prompt", system,
    "--json-schema", JSON.stringify(schema),
  ];
}

/** Parses `claude -p --output-format json` output into structured data. Exported for tests. */
export function parseClaudeOutput(stdout: string): LlmResponse {
  let envelope: { is_error?: boolean; structured_output?: unknown; result?: unknown; total_cost_usd?: number; subtype?: string };
  try {
    envelope = JSON.parse(stdout) as typeof envelope;
  } catch {
    throw new ProviderError(`claude returned non-JSON output: ${stdout.slice(0, 200)}`);
  }
  if (envelope.is_error) throw new ProviderError(`claude reported an error (${envelope.subtype ?? "unknown"}): ${String(envelope.result ?? "").slice(0, 200)}`);
  let data = envelope.structured_output;
  if (data === undefined && typeof envelope.result === "string") {
    try {
      data = JSON.parse(envelope.result);
    } catch {
      throw new ProviderError("claude returned no structured output");
    }
  }
  if (data === undefined || data === null || typeof data !== "object") throw new ProviderError("claude returned no structured output");
  return { data, ...(typeof envelope.total_cost_usd === "number" ? { costUsd: envelope.total_cost_usd } : {}) };
}

/** Runs the user's own Claude Code CLI (`claude -p`): their subscription, no API key. */
export class ClaudeCliProvider implements LlmProvider {
  readonly name = "claude-code";
  readonly model: string;
  private readonly options: ClaudeCliOptions;

  constructor(options: ClaudeCliOptions) {
    this.options = options;
    this.model = options.model;
  }

  complete(request: LlmRequest): Promise<LlmResponse> {
    mkdirSync(this.options.sandboxDir, { recursive: true });
    const args = claudeArgs(this.model, request.system, request.schema);
    const command = this.options.command ?? resolveClaudeExecutable();
    if (!command) {
      return Promise.reject(new ProviderError('Claude Code was not found on PATH. Install it (https://docs.claude.com/claude-code) and run "claude" once to sign in.'));
    }
    return new Promise((resolve, reject) => {
      // No shell: every argument reaches claude verbatim; the prompt (with repo excerpts) goes through stdin.
      const child = spawn(command, args, { cwd: path.resolve(this.options.sandboxDir), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      let stdout = "";
      let stderr = "";
      let settled = false;
      const fail = (e: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        stop();
        reject(e);
      };
      // SIGTERM first, SIGKILL if it ignores that, so a hung CLI never outlives the review.
      const stop = (): void => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        child.kill();
        setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        }, KILL_GRACE_MS).unref();
      };
      const timer = setTimeout(
        () => fail(new ProviderError(`claude timed out after ${Math.round((this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS) / 1000)} s`)),
        this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      );
      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString("utf8");
        if (stdout.length > MAX_OUTPUT) fail(new ProviderError("claude produced more output than expected; stopped"));
      });
      child.stderr.on("data", (d: Buffer) => {
        if (stderr.length < MAX_STDERR) stderr += d.toString("utf8");
      });
      child.on("error", (e) => fail(new ProviderError(`could not start "${command}" (${e.message}). Is Claude Code installed and on PATH?`)));
      // A CLI that exits early (e.g. not signed in) closes stdin: report it instead of crashing the run.
      child.stdin.on("error", (e) => fail(new ProviderError(`claude stopped reading its input (${e.message}): ${stderr.trim().slice(0, 300)}`)));
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code !== 0 && stdout.trim() === "") {
          reject(new ProviderError(`claude exited with code ${code}: ${stderr.trim().slice(0, 300)}`));
          return;
        }
        try {
          resolve(parseClaudeOutput(stdout));
        } catch (e) {
          reject(e);
        }
      });
      child.stdin.end(request.prompt, "utf8");
    });
  }
}
