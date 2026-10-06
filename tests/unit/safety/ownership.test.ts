import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createProof, readProof, verifyOwnership } from "../../../src/safety/ownership.js";
import { startMockServer } from "../../helpers/mock-server.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "whsquad-own-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const TOKEN = "0123456789abcdef0123456789abcdef";
const WRONG = "ffffffffffffffffffffffffffffffff";
const noTxt = async (): Promise<string[][]> => {
  throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
};
const noFetch = async () => ({ status: 404, body: "" });

describe("proof file lifecycle", () => {
  it("creates a 128-bit hex token in .whsquad/proof.json", () => {
    const { token, file } = createProof("example.com", dir);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
    expect(file).toBe(join(dir, ".whsquad", "proof.json"));
    const saved = JSON.parse(readFileSync(file, "utf8")) as { domain: string; token: string };
    expect(saved).toMatchObject({ domain: "example.com", token });
    if (process.platform !== "win32") expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it("reuses the token for the same domain and rotates for a different one", () => {
    const a = createProof("example.com", dir);
    expect(createProof("example.com", dir).token).toBe(a.token);
    const b = createProof("other.com", dir);
    expect(b.token).not.toBe(a.token);
    expect(readProof(dir)?.domain).toBe("other.com");
  });

  it("readProof returns null for missing, corrupt, or malformed files", () => {
    expect(readProof(dir)).toBeNull();
    mkdirSync(join(dir, ".whsquad"));
    writeFileSync(join(dir, ".whsquad", "proof.json"), "{not json");
    expect(readProof(dir)).toBeNull();
    writeFileSync(join(dir, ".whsquad", "proof.json"), JSON.stringify({ domain: "x", token: "short" }));
    expect(readProof(dir)).toBeNull();
    writeFileSync(join(dir, ".whsquad", "proof.json"), JSON.stringify(null));
    expect(readProof(dir)).toBeNull();
    expect(existsSync(join(dir, ".whsquad", "proof.json"))).toBe(true);
  });

  it("regenerates when the existing proof file is corrupt", () => {
    mkdirSync(join(dir, ".whsquad"));
    writeFileSync(join(dir, ".whsquad", "proof.json"), "garbage");
    expect(createProof("example.com", dir).token).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("verifyOwnership: automatic methods", () => {
  it("does not auto-verify x.localhost: some resolvers send it to a public address", async () => {
    const res = await verifyOwnership(new URL("http://app.localhost"), { resolveTxt: noTxt, fetcher: noFetch, token: "t".repeat(32) });
    expect(res.verified).toBe(false);
  });

  it("treats hex-looking real domains as domains, not IP literals", async () => {
    const res = await verifyOwnership(new URL("https://face.de"), { resolveTxt: noTxt, fetcher: noFetch, token: "t".repeat(32) });
    expect(res.detail).not.toContain("can never be verified");
  });

  it("ignores a stored proof token that was created for a different domain", async () => {
    const { token } = createProof("mine.example", dir);
    const res = await verifyOwnership(new URL("https://other.example"), {
      dir,
      resolveTxt: async () => [[`whsquad-verify=${token}`]],
      fetcher: async () => ({ status: 200, body: token }),
    });
    expect(res).toMatchObject({ verified: false, method: "none" });
  });

  it.each(["http://localhost:3000", "http://127.0.0.1:8080", "http://127.5.5.5", "http://[::1]:3000"])(
    "auto-verifies loopback target %s",
    async (url) => {
      const res = await verifyOwnership(new URL(url), { resolveTxt: noTxt, fetcher: noFetch });
      expect(res).toMatchObject({ verified: true, method: "loopback" });
    },
  );

  it("refuses RFC1918 without allowPrivate and accepts with it", async () => {
    const t = new URL("http://192.168.1.10");
    const denied = await verifyOwnership(t, {});
    expect(denied).toMatchObject({ verified: false, method: "none" });
    expect(denied.detail).toMatch(/allow-private/i);
    expect(await verifyOwnership(t, { allowPrivate: true })).toMatchObject({
      verified: true,
      method: "private-allowed",
    });
  });

  it("never verifies metadata or link-local literals", async () => {
    for (const host of ["169.254.169.254", "169.254.1.1", "[fd00:ec2::254]"]) {
      const res = await verifyOwnership(new URL(`http://${host}`), { allowPrivate: true, token: TOKEN });
      expect(res).toMatchObject({ verified: false, method: "none" });
    }
  });
});

describe("verifyOwnership: DNS TXT", () => {
  const target = new URL("https://app.example.com/path");

  it("verifies when _whsquad.<host> TXT carries the token", async () => {
    const queried: string[] = [];
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: async (name) => {
        queried.push(name);
        return [["v=spf1 -all"], [`whsquad-verify=${TOKEN.slice(0, 16)}`, TOKEN.slice(16)]];
      },
      fetcher: noFetch,
    });
    expect(queried).toEqual(["_whsquad.app.example.com"]);
    expect(res).toMatchObject({ verified: true, method: "dns-txt" });
  });

  it("rejects a wrong token and never echoes the real token", async () => {
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: async () => [[`whsquad-verify=${WRONG}`]],
      fetcher: noFetch,
    });
    expect(res).toMatchObject({ verified: false, method: "none" });
    expect(res.detail).not.toContain(TOKEN);
    expect(res.detail).not.toContain(WRONG);
  });

  it("rejects a token that is only a prefix or has trailing junk", async () => {
    for (const record of [`whsquad-verify=${TOKEN.slice(0, 31)}`, `whsquad-verify=${TOKEN}0`, `other=${TOKEN}`]) {
      const res = await verifyOwnership(target, { token: TOKEN, resolveTxt: async () => [[record]], fetcher: noFetch });
      expect(res.verified).toBe(false);
    }
  });
});

describe("verifyOwnership: well-known file", () => {
  const target = new URL("https://app.example.com/");

  it("verifies when the well-known body contains the token", async () => {
    const urls: string[] = [];
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: noTxt,
      fetcher: async (url) => {
        urls.push(url);
        return { status: 200, body: `\n  whsquad-verify=${TOKEN}  \n` };
      },
    });
    expect(urls).toEqual(["https://app.example.com/.well-known/whsquad.txt"]);
    expect(res).toMatchObject({ verified: true, method: "well-known" });
  });

  it("accepts a bare token body", async () => {
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: noTxt,
      fetcher: async () => ({ status: 200, body: TOKEN }),
    });
    expect(res.method).toBe("well-known");
  });

  it("rejects wrong token, non-200 status, and fetch errors", async () => {
    const bodies = [
      { status: 200, body: WRONG },
      { status: 404, body: TOKEN },
    ];
    for (const b of bodies) {
      const res = await verifyOwnership(target, { token: TOKEN, resolveTxt: noTxt, fetcher: async () => b });
      expect(res).toMatchObject({ verified: false, method: "none" });
    }
    const failing = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: noTxt,
      fetcher: async () => {
        throw new Error("network down");
      },
    });
    expect(failing.verified).toBe(false);
    expect(failing.detail).not.toContain(TOKEN);
  });

  it("caps the inspected body at 1KB (token beyond the cap is ignored)", async () => {
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: noTxt,
      fetcher: async () => ({ status: 200, body: `${"x ".repeat(600)}${TOKEN}` }),
    });
    expect(res.verified).toBe(false);
  });

  it("falls through to well-known when DNS lookup fails or has wrong value", async () => {
    const res = await verifyOwnership(target, {
      token: TOKEN,
      resolveTxt: async () => [[`whsquad-verify=${WRONG}`]],
      fetcher: async () => ({ status: 200, body: TOKEN }),
    });
    expect(res.method).toBe("well-known");
  });
});

describe("verifyOwnership: token sourcing", () => {
  it("reads the token from .whsquad/proof.json when opts.token is absent", async () => {
    const { token } = createProof("app.example.com", dir);
    const res = await verifyOwnership(new URL("https://app.example.com"), {
      dir,
      resolveTxt: async () => [[`whsquad-verify=${token}`]],
      fetcher: noFetch,
    });
    expect(res).toMatchObject({ verified: true, method: "dns-txt" });
  });

  it("fails cleanly with no token available", async () => {
    const res = await verifyOwnership(new URL("https://app.example.com"), { dir, resolveTxt: noTxt, fetcher: noFetch });
    expect(res).toMatchObject({ verified: false, method: "none" });
    expect(res.detail).toMatch(/proof|token/i);
  });

  it("never logs the token", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => undefined),
    );
    await verifyOwnership(new URL("https://app.example.com"), {
      token: TOKEN,
      resolveTxt: async () => [[`whsquad-verify=${TOKEN}`]],
      fetcher: noFetch,
    });
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });
});

describe("verifyOwnership: default transports", () => {
  it("uses the safe HTTP client for the default fetcher (refuses loopback-resolving hosts)", async () => {
    const server = await startMockServer((_req, res) => res.end(TOKEN));
    try {
      // A public-looking name that resolves to loopback must be refused by the SSRF guard.
      const res = await verifyOwnership(new URL(`https://app.example.com:${server.port}`), {
        token: TOKEN,
        resolveTxt: noTxt,
        resolver: async () => [{ address: "127.0.0.1", family: 4 }],
      });
      expect(res.verified).toBe(false);
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it("reaches DNS with the default resolveTxt without throwing", async () => {
    const res = await verifyOwnership(new URL("https://nonexistent.invalid"), {
      token: TOKEN,
      fetcher: noFetch,
    });
    expect(res.verified).toBe(false);
  });
});
