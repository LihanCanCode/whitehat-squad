/** AI coding-agent configuration files: hidden Unicode, unpinned MCP launchers, literal MCP credentials. */
import { lineOf } from "../../core/finding.js";
import { parseJsonc } from "./jsonc.js";

const MAX_DECODED = 120;

export interface HiddenText {
  /** 1-based line of the first hidden character. */
  readonly line: number;
  readonly count: number;
  /** Distinct code points found, e.g. "U+200B" (at most 8). */
  readonly codepoints: readonly string[];
  /** Text smuggled in Unicode tag characters, decoded to ASCII; undefined when none. */
  readonly decoded?: string;
}

const HIDDEN = /[​-‏⁠-⁤‪-‮⁦-⁩\u{E0000}-\u{E007F}]/gu;
/** Legitimate uses: emoji ZWJ sequences, and subdivision-flag emoji built from tag characters. */
const EMOJI_ZWJ = /(?<=[\p{Extended_Pictographic}️\u{1F3FB}-\u{1F3FF}])‍(?=\p{Extended_Pictographic})/gu;
const FLAG_TAGS = /\u{1F3F4}[\u{E0020}-\u{E007E}]+\u{E007F}/gu;
const RTL_LETTER = /[\p{Script=Hebrew}\p{Script=Arabic}]/u;
const RTL_MARKS = new Set([0x200c, 0x200e, 0x200f]);

function isTag(cp: number): boolean {
  return cp >= 0xe0020 && cp <= 0xe007e;
}

export function findHiddenText(text: string): HiddenText | null {
  const rtl = RTL_LETTER.test(text);
  const masked = text.replace(FLAG_TAGS, (m) => " ".repeat(m.length)).replace(EMOJI_ZWJ, " ");
  let first = -1;
  let count = 0;
  const seen = new Set<string>();
  let decoded = "";
  for (const m of masked.matchAll(HIDDEN)) {
    const cp = m[0].codePointAt(0) ?? 0;
    if (rtl && RTL_MARKS.has(cp)) continue;
    if (first < 0) first = m.index ?? 0;
    count++;
    if (seen.size < 8) seen.add(`U+${cp.toString(16).toUpperCase()}`);
    if (isTag(cp)) decoded += String.fromCharCode(cp - 0xe0000);
  }
  if (count === 0) return null;
  const shown = decoded.length > MAX_DECODED ? `${decoded.slice(0, MAX_DECODED)}...` : decoded;
  return { line: lineOf(masked, first), count, codepoints: [...seen], ...(decoded ? { decoded: shown } : {}) };
}

const AGENT_FILE = /(?:^|\/)(?:\.cursorrules|\.windsurfrules|\.clinerules|CLAUDE\.md|AGENTS\.md|\.github\/copilot-instructions\.md|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.mcp\.json)$|(?:^|\/)\.cursor\/rules\/.+|(?:^|\/)\.clinerules\/.+/;
const MCP_FILE = /(?:^|\/)(?:\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json)$/;

export function isAgentConfigPath(path: string): boolean {
  return AGENT_FILE.test(path);
}

export function isMcpConfigPath(path: string): boolean {
  return MCP_FILE.test(path);
}

export interface McpServer {
  readonly name: string;
  readonly command?: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Reads `mcpServers` (Claude, Cursor), `servers` (VS Code) or `mcp.servers`; [] when unreadable. */
export function readMcpServers(text: string): McpServer[] {
  let json: unknown;
  try {
    json = parseJsonc(text);
  } catch {
    return [];
  }
  if (!isRecord(json)) return [];
  const mcp = isRecord(json["mcp"]) ? json["mcp"] : undefined;
  const table = [json["mcpServers"], json["servers"], mcp?.["servers"]].find(isRecord);
  if (!table) return [];
  const out: McpServer[] = [];
  for (const [name, raw] of Object.entries(table)) {
    if (!isRecord(raw)) continue;
    const args = Array.isArray(raw["args"]) ? raw["args"].filter((a): a is string => typeof a === "string") : [];
    const env: Record<string, string> = {};
    if (isRecord(raw["env"])) {
      for (const [k, v] of Object.entries(raw["env"])) if (typeof v === "string") env[k] = v;
    }
    out.push({ name, ...(typeof raw["command"] === "string" ? { command: raw["command"] } : {}), args, env });
  }
  return out;
}

export interface UnpinnedLauncher {
  readonly runner: string;
  readonly spec: string;
}

const RUNNERS: ReadonlySet<string> = new Set(["npx", "bunx", "uvx", "pipx"]);
const PINNED_NPM = /^(?:@[^/@]+\/)?[^@/]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;
const PINNED_PY = /^[^@=]+(?:==|@)\d[\w.+-]*$/;

function baseName(cmd: string): string {
  const name = cmd.slice(Math.max(cmd.lastIndexOf("/"), cmd.lastIndexOf("\\")) + 1).toLowerCase();
  return name.replace(/\.(?:cmd|exe|bat)$/, "");
}

/** The package spec following the runner's flags (npx -y pkg -> pkg); also handles `-p pkg` and `pnpm dlx pkg`. */
function packageSpec(words: readonly string[]): string | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i] ?? "";
    if (w === "-p" || w === "--package") return words[i + 1];
    if (w.startsWith("--package=")) return w.slice("--package=".length);
    if (w.startsWith("-")) continue;
    return w;
  }
  return undefined;
}

/** Is this MCP server started from a registry package without a pinned version? */
export function unpinnedLauncher(server: McpServer): UnpinnedLauncher | null {
  const words = [...(server.command ? [server.command] : []), ...server.args];
  const at = words.findIndex((w) => RUNNERS.has(baseName(w)) || /^(?:pnpm|yarn)$/.test(baseName(w)));
  const head = words[at];
  if (at < 0 || head === undefined) return null;
  let runner = baseName(head);
  let rest = words.slice(at + 1);
  if (runner === "pnpm" || runner === "yarn") {
    if (rest[0] !== "dlx") return null;
    rest = rest.slice(1);
    runner = `${runner} dlx`;
  }
  const spec = packageSpec(rest);
  if (!spec || /^(?:\.|\/|~|[A-Za-z]:)/.test(spec) || /^(?:file|git\+|https?:|github:)/.test(spec)) return null;
  const pinned = runner === "uvx" || runner === "pipx" ? PINNED_PY.test(spec) : PINNED_NPM.test(spec);
  return pinned ? null : { runner, spec };
}

const SECRET_NAME = /(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD)$/i;
const PLACEHOLDER = /^(?:x+|\*+|\.{3}|<.*>|your[-_ ].*|.*_here|changeme|change-me|todo|redacted|none|null)$/i;
const REFERENCE = /^\$|\$\{|^%.*%$/;
/** Provider token shapes the secrets agent already reports; we stay out of its way. */
const PROVIDER_TOKEN =
  /^(?:sk-|sk_live_|sk_test_|pk_live_|rk_live_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|AKIA|ASIA|AIza|npm_|hf_|SG\.|sbp_|sb_secret_|eyJ|dop_v1_|shpat_|lin_api_|pplx-|r8_|gsk_|fc-)/;

/** Env entries that look like a credential: secret-ish name, literal value, not a placeholder or provider token. */
export function literalSecretEnv(server: McpServer): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const [name, raw] of Object.entries(server.env)) {
    const value = raw.trim();
    if (!SECRET_NAME.test(name) || value === "") continue;
    if (REFERENCE.test(value) || PLACEHOLDER.test(value) || PROVIDER_TOKEN.test(value) || /^https?:\/\//i.test(value)) continue;
    out.push({ name, value });
  }
  return out;
}
