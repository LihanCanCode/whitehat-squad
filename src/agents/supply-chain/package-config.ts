/** Line-oriented checks for .npmrc, .yarnrc.yml and .yarnrc that weaken registry security. */

export interface ConfigIssue {
  readonly line: number;
  readonly snippet: string;
  /** Short reason, used in the finding title. */
  readonly what: string;
}

const LOOPBACK = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)/i;
const HTTP_URL = /^http:\/\//i;
const LITERAL_TOKEN = /^\s*[^#;\n]*?\b(?:_authToken|_auth|_password)\s*=\s*(\S+)\s*$/;

function unquote(v: string): string {
  return v.trim().replace(/^["']|["']$/g, "");
}

function isHttpRegistry(url: string): boolean {
  return HTTP_URL.test(url) && !LOOPBACK.test(url);
}

function npmrcIssues(lines: readonly string[]): ConfigIssue[] {
  const out: ConfigIssue[] = [];
  let alwaysAuthLine = 0;
  let literalToken = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) return;
    const kv = /^([^=\s][^=]*?)\s*=\s*(.*)$/.exec(line);
    if (!kv) return;
    const key = (kv[1] ?? "").toLowerCase();
    const value = unquote(kv[2] ?? "");
    if ((key === "registry" || key.endsWith(":registry")) && isHttpRegistry(value)) {
      out.push({ line: i + 1, snippet: line, what: "registry served over plain http" });
    } else if (key === "strict-ssl" && value.toLowerCase() === "false") {
      out.push({ line: i + 1, snippet: line, what: "TLS certificate checking disabled (strict-ssl=false)" });
    } else if (key === "always-auth" && value.toLowerCase() === "true") {
      alwaysAuthLine = i + 1;
    }
    const token = LITERAL_TOKEN.exec(line)?.[1];
    if (token && !unquote(token).includes("${")) literalToken = true;
  });
  if (alwaysAuthLine > 0 && literalToken) {
    out.push({ line: alwaysAuthLine, snippet: "always-auth=true", what: "always-auth=true combined with a hardcoded token" });
  }
  return out;
}

function yarnrcYmlIssues(lines: readonly string[]): ConfigIssue[] {
  const out: ConfigIssue[] = [];
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line.startsWith("#")) return;
    const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
    if (server && isHttpRegistry(unquote(server[1] ?? ""))) {
      out.push({ line: i + 1, snippet: line, what: "registry served over plain http" });
    }
    if (/^enableStrictSsl\s*:\s*false\b/i.test(line)) {
      out.push({ line: i + 1, snippet: line, what: "TLS certificate checking disabled (enableStrictSsl: false)" });
    }
  });
  return out;
}

function yarnrcClassicIssues(lines: readonly string[]): ConfigIssue[] {
  const out: ConfigIssue[] = [];
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line.startsWith("#")) return;
    const reg = /^(?:\S*:)?registry\s+(.+)$/.exec(line);
    if (reg && isHttpRegistry(unquote(reg[1] ?? ""))) {
      out.push({ line: i + 1, snippet: line, what: "registry served over plain http" });
    }
    if (/^strict-ssl\s+false\b/i.test(line)) {
      out.push({ line: i + 1, snippet: line, what: "TLS certificate checking disabled (strict-ssl false)" });
    }
  });
  return out;
}

export function packageConfigIssues(fileName: string, text: string): ConfigIssue[] {
  const lines = text.split(/\r?\n/);
  if (fileName === ".npmrc") return npmrcIssues(lines);
  if (fileName === ".yarnrc.yml") return yarnrcYmlIssues(lines);
  if (fileName === ".yarnrc") return yarnrcClassicIssues(lines);
  return [];
}

export const PACKAGE_CONFIG_FILES: ReadonlySet<string> = new Set([".npmrc", ".yarnrc.yml", ".yarnrc"]);
