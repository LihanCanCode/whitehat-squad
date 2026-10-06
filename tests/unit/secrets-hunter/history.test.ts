import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { agent } from "../../../src/agents/secrets-hunter/index.js";
import { gitLogArgs, scanGitHistory, unquoteGitPath } from "../../../src/agents/secrets-hunter/history.js";
import { memContext } from "../../helpers/memfs.js";
import { expectNoRawSecrets, SAMPLES } from "./fakes.js";

const git = (cwd: string, ...args: string[]): void => {
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t.test", "-c", "commit.gpgsign=false", ...args], {
    cwd, stdio: "ignore",
  });
};

let gitAvailable = true;
try { execFileSync("git", ["--version"], { stdio: "ignore" }); } catch { gitAvailable = false; }

describe.skipIf(!gitAvailable)("SEC-102 git history", () => {
  let repo = "";
  let plain = "";
  const secret = SAMPLES["SEC-004"] as string;

  beforeAll(() => {
    repo = mkdtempSync(path.join(tmpdir(), "whsq-hist-"));
    plain = mkdtempSync(path.join(tmpdir(), "whsq-plain-"));
    git(repo, "init", "-q");
    writeFileSync(path.join(repo, "pay.ts"), `const key = "${secret}";\nexport {};\n`);
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "oops");
    writeFileSync(path.join(repo, "pay.ts"), `const key = process.env.KEY;\nexport {};\n`);
    git(repo, "commit", "-q", "-am", "fix");
  });
  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
    rmSync(plain, { recursive: true, force: true });
  });

  const ctxFor = (root: string | undefined, gitHistory: boolean) => ({
    ...memContext({ "pay.ts": "const key = process.env.KEY;\n" }),
    ...(root ? { root } : {}),
    options: { gitHistory, maxRequests: 1 },
  });

  it("reports a secret that was removed but lives on in history", async () => {
    const ctx = ctxFor(repo, true);
    const findings = await agent.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SEC-102", severity: "critical" });
    expect(findings[0]?.evidence[0]).toMatchObject({ file: "pay.ts", line: 1 });
    expect(findings[0]?.evidence[0]?.snippet).toMatch(/[0-9a-f]{7}/);
    expect(findings[0]?.explanation).toMatch(/history/i);
    expect(findings[0]?.fix.agentPrompt).toMatch(/rotate/i);
    expect(ctx.secrets.has(secret)).toBe(true);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("does nothing unless gitHistory is enabled", async () => {
    expect(await agent.run(ctxFor(repo, false))).toEqual([]);
  });

  it("does nothing without a root", async () => {
    expect(await agent.run(ctxFor(undefined, true))).toEqual([]);
  });

  it("returns [] when the directory is not a git repository", async () => {
    expect(await agent.run(ctxFor(plain, true))).toEqual([]);
  });

  it("returns [] when the root does not exist", async () => {
    expect(await agent.run(ctxFor(path.join(plain, "missing"), true))).toEqual([]);
  });

  it("skips secrets that are still in the working tree (already reported as SEC-0xx)", async () => {
    const ctx = { ...ctxFor(repo, true), files: memContext({ "pay.ts": `const key = "${secret}";\n` }).files };
    const findings = await agent.run(ctx);
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-004"]);
  });
});

describe("git path unquoting", () => {
  it("unquotes git's C-style quoted paths", () => {
    expect(unquoteGitPath('"a/with space.ts"')).toBe("a/with space.ts");
    expect(unquoteGitPath('"a/caf\\303\\251.ts"')).toBe("a/caf\u00e9.ts");
    expect(unquoteGitPath('"a/tab\\there \\"q\\" back\\\\slash"')).toBe('a/tab\there "q" back\\slash');
    expect(unquoteGitPath("a/plain.ts\t")).toBe("a/plain.ts");
    expect(unquoteGitPath("a/with space.ts")).toBe("a/with space.ts");
  });
});

describe("git log hardening arguments", () => {
  it("keeps every hardening flag exactly", () => {
    expect(gitLogArgs("/r", 500)).toEqual([
      "-C", "/r",
      "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
      "log", "-p", "--max-count=500", "--no-color", "--no-ext-diff", "--no-textconv",
      "--format=@@whsq-commit %H",
    ]);
  });
});

function captureStderr(): { writes: string[]; restore: () => void } {
  const writes: string[] = [];
  const spy = vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stderr.write);
  return { writes, restore: () => spy.mockRestore() };
}

describe.skipIf(!gitAvailable)("SEC-102 history scanning limits and quoting", () => {
  const dirs: string[] = [];
  const secret = SAMPLES["SEC-004"] as string;
  const mk = (): string => {
    const d = mkdtempSync(path.join(tmpdir(), "whsq-hist2-"));
    dirs.push(d);
    git(d, "init", "-q");
    return d;
  };
  const commitSecretThenRemove = (repo: string, file: string, extra?: () => void): void => {
    writeFileSync(path.join(repo, file), `const key = "${secret}";\n`);
    extra?.();
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "first");
    writeFileSync(path.join(repo, file), "export {};\n");
    git(repo, "commit", "-q", "-am", "remove key");
  };
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  it("finds a secret in a file whose name has spaces and non-ASCII characters", async () => {
    const repo = mk();
    mkdirSync(path.join(repo, "dir one"));
    commitSecretThenRemove(repo, path.join("dir one", "caf\u00e9 pay.ts"));
    const hits = await scanGitHistory(repo, new Set());
    expect(hits).toHaveLength(1);
    expect(hits[0]?.file).toBe("dir one/caf\u00e9 pay.ts");
  });

  it("processes what it read when the byte cap is hit and warns accurately", async () => {
    const repo = mk();
    commitSecretThenRemove(repo, "pay.ts", () => {
      const lines = Array.from({ length: 6000 }, (_, i) => `line ${i} ${"z".repeat(60)}`);
      writeFileSync(path.join(repo, "big.txt"), lines.join("\n"));
    });
    const cap = captureStderr();
    try {
      const hits = await scanGitHistory(repo, new Set(), { maxBytes: 20_000 });
      expect(hits.map((h) => h.file)).toEqual(["pay.ts"]);
      const warning = cap.writes.join("");
      expect(warning).toMatch(/stopped after \d+ commits?/i);
      expect(warning).toMatch(/\d+(?:\.\d+)? (?:KB|MB)/);
      expect(warning).toMatch(/older commits were not checked/i);
      expect(warning).not.toMatch(/too large or too slow/i);
    } finally {
      cap.restore();
    }
  });

  it("warns nothing when the history fits the cap", async () => {
    const repo = mk();
    commitSecretThenRemove(repo, "pay.ts");
    const cap = captureStderr();
    try {
      expect(await scanGitHistory(repo, new Set())).toHaveLength(1);
      expect(cap.writes).toEqual([]);
    } finally {
      cap.restore();
    }
  });

  it("stops on the time limit and says it was the time limit", async () => {
    const repo = mk();
    commitSecretThenRemove(repo, "pay.ts");
    const cap = captureStderr();
    try {
      await scanGitHistory(repo, new Set(), { timeoutMs: 1 });
      expect(cap.writes.join("")).toMatch(/time limit/i);
    } finally {
      cap.restore();
    }
  });
});
