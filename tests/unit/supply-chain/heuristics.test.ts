import { describe, expect, it } from "vitest";
import { checkTyposquat, slopBase } from "../../../src/agents/supply-chain/names.js";
import { classifySpec } from "../../../src/agents/supply-chain/spec.js";
import { findRisky } from "../../../src/data/risky-packages.js";
import { POPULAR_PACKAGES } from "../../../src/data/popular-packages.js";

describe("checkTyposquat", () => {
  it("flags a single-character typo", () => {
    expect(checkTyposquat("lodahs")?.target).toBe("lodash");
    expect(checkTyposquat("expresss")?.target).toBe("express");
  });
  it("flags homoglyphs", () => {
    expect(checkTyposquat("react-d0m")?.kind).toBe("homoglyph");
    expect(checkTyposquat("l0dash")?.target).toBe("lodash");
    expect(checkTyposquat("reactjs-dorn")).toBeNull();
  });
  it("flags scope confusion", () => {
    const hit = checkTyposquat("@types-react");
    expect(hit?.kind).toBe("scope-confusion");
    expect(hit?.target).toBe("@types/react");
  });
  it("never flags a popular package or an allowlisted lookalike", () => {
    expect(checkTyposquat("react")).toBeNull();
    expect(checkTyposquat("preact")).toBeNull();
    expect(checkTyposquat("zod")).toBeNull();
    expect(checkTyposquat("@supabase/supabase-js")).toBeNull();
  });
  it("flags only single-edit lookalikes, never distance 2", () => {
    expect(checkTyposquat("rexct")?.target).toBe("react");
    expect(checkTyposquat("rxcts")).toBeNull();
    // A real, unrelated package two edits from bcryptjs must not be reported.
    expect(checkTyposquat("bcrypt-ts")).toBeNull();
  });
  it("ignores very short names and unrelated names", () => {
    expect(checkTyposquat("ab")).toBeNull();
    expect(checkTyposquat("my-company-internal-widget")).toBeNull();
  });
  it("does not flag a sibling inside the same scope", () => {
    expect(checkTyposquat("@radix-ui/react-tab")).toBeNull();
  });
  it("reports distance", () => {
    expect(checkTyposquat("lodahs")?.distance).toBe(1);
    expect(checkTyposquat("tailwindcsss")?.distance).toBe(1);
  });
});

describe("slopBase", () => {
  it("matches names AI assistants invent", () => {
    expect(slopBase("openai-utils")).toBe("openai");
    expect(slopBase("stripe-helpers")).toBe("stripe");
    expect(slopBase("supabase-sdk-js")).toBe("supabase");
    expect(slopBase("zod-easy")).toBe("zod");
    expect(slopBase("react-form-hooks")).toBe("react");
  });
  it("ignores popular packages and plain names", () => {
    expect(slopBase("react")).toBeNull();
    expect(slopBase("my-utils")).toBeNull();
    expect(slopBase("lodash")).toBeNull();
  });
});

describe("classifySpec", () => {
  it("accepts plain semver ranges and workspace protocols", () => {
    for (const s of ["^1.2.3", "~2.0.0", "1.0.0", ">=1 <2", "workspace:*", "npm:foo@^1", "next"]) {
      expect(classifySpec(s, "")).toBeNull();
    }
  });
  it("flags wildcards", () => {
    for (const s of ["*", "latest", "", "x"]) expect(classifySpec(s, "")?.kind).toBe("wildcard");
  });
  it("flags git protocol, tarballs and unpinned github shorthand", () => {
    expect(classifySpec("git://github.com/a/b.git", "")?.kind).toBe("git");
    expect(classifySpec("git+https://github.com/a/b.git", "")?.kind).toBe("git");
    expect(classifySpec("https://example.com/pkg.tgz", "")?.kind).toBe("tarball");
    expect(classifySpec("http://example.com/pkg.tgz", "")?.kind).toBe("tarball");
    expect(classifySpec("user/repo", "")?.kind).toBe("github-shorthand");
    expect(classifySpec("github:user/repo#main", "")?.kind).toBe("github-shorthand");
  });
  it("accepts commit-pinned git dependencies", () => {
    expect(classifySpec("git+https://github.com/a/b.git#0123456789abcdef0123456789abcdef01234567", "")).toBeNull();
    expect(classifySpec("user/repo#0123456", "")).toBeNull();
  });
  it("flags file: paths that leave the repo only", () => {
    expect(classifySpec("file:../shared", "")?.kind).toBe("file-outside");
    expect(classifySpec("file:../../../x", "packages/a")?.kind).toBe("file-outside");
    expect(classifySpec("file:../../x", "packages/a")).toBeNull();
    expect(classifySpec("file:/etc/pkg", "")?.kind).toBe("file-outside");
    expect(classifySpec("file:C:/dev/pkg", "")?.kind).toBe("file-outside");
    expect(classifySpec("file:../shared", "packages/a")).toBeNull();
    expect(classifySpec("file:./vendor/x.tgz", "")).toBeNull();
  });
});

describe("risky list", () => {
  it("matches exact name@version only", () => {
    expect(findRisky("event-stream", "3.3.6")).toBeDefined();
    expect(findRisky("event-stream", "4.0.1")).toBeUndefined();
    expect(findRisky("left-pad", "1.3.0")).toBeUndefined();
  });
  it("popular list contains the ecosystem staples", () => {
    for (const n of ["react", "next", "zod", "@supabase/supabase-js", "stripe", "openai", "tailwindcss"]) {
      expect(POPULAR_PACKAGES.has(n)).toBe(true);
    }
    expect(POPULAR_PACKAGES.size).toBeGreaterThan(300);
  });
});
