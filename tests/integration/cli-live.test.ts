import { describe, expect, it, vi } from "vitest";
import { parseCli } from "../../src/cli/args.js";
import { scanTarget } from "../../src/cli/run-scan.js";
import type { HttpResult } from "../../src/core/types.js";

const created = vi.hoisted(() => ({ options: [] as { maxRequests?: number; allowBackendHosts?: boolean }[] }));

vi.mock("../../src/safety/ownership.js", async (original) => ({
  ...(await original<typeof import("../../src/safety/ownership.js")>()),
  verifyOwnership: async () => ({ verified: true, method: "localhost", detail: "test" }),
}));

vi.mock("../../src/safety/http-client.js", async (original) => ({
  ...(await original<typeof import("../../src/safety/http-client.js")>()),
  createSafeHttpClient: (o: { maxRequests?: number; allowBackendHosts?: boolean }) => {
    created.options.push(o);
    const respond = async (url: string): Promise<HttpResult> => ({ url, status: 404, headers: {}, setCookies: [], body: "" });
    return { get: respond, head: respond };
  },
}));

describe("live scans", () => {
  const optionsFor = (...argv: string[]) => parseCli(["scan", "http://localhost:3000", ...argv]).options;

  it("passes --max-requests to the safe HTTP client and into ScanOptions", async () => {
    created.options.length = 0;
    const report = await scanTarget("http://localhost:3000", optionsFor("--max-requests", "7"), process.cwd());
    expect(created.options.at(-1)?.maxRequests).toBe(7);
    expect(report.mode).toBe("live");
  });

  it("counts the requests the scan sent and prints the live flags in verify commands", async () => {
    const report = await scanTarget("http://localhost:3000", optionsFor("--probe-database", "--allow-private"), process.cwd());
    expect(report.coverage?.liveRequests).toBeGreaterThan(0);
    expect(report.scanOptions).toEqual({ gitHistory: false, probeDatabase: true, allowPrivate: true });
    for (const f of report.findings) expect(f.verify.command).toMatch(/--probe-database --allow-private$/);
    expect(created.options.at(-1)?.allowBackendHosts).toBe(true);
  });
});
