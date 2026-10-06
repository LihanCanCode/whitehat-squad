import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/supply-chain/index.js";
import { matchAdvisories, recommendedFix } from "../../../src/agents/supply-chain/framework-advisories.js";
import { compareVersions, parseVersion, satisfies } from "../../../src/agents/supply-chain/semver.js";
import { ADVISORY_SNAPSHOT_DATE, FRAMEWORK_ADVISORIES } from "../../../src/data/advisories.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext } from "../../helpers/memfs.js";

const pkg = (deps: Record<string, string>): string => JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps }, null, 2);
const lockWith = (versions: Record<string, string>): string =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app" },
      ...Object.fromEntries(Object.entries(versions).map(([n, v]) => [
        `node_modules/${n}`,
        { version: v, resolved: `https://registry.npmjs.org/${n}/-/x-${v}.tgz`, integrity: "sha512-abc" },
      ])),
    },
  });

async function scan(files: Record<string, string>) {
  return agent.run(memContext(files));
}
const sup010 = (f: readonly Finding[]): Finding[] => f.filter((x) => x.ruleId === "SUP-010");
const byGhsa = (f: readonly Finding[], ghsa: string): Finding | undefined => f.find((x) => x.explanation.includes(ghsa));

describe("advisory data integrity", () => {
  it("has a snapshot date and well-formed GHSA ids", () => {
    expect(ADVISORY_SNAPSHOT_DATE).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const a of FRAMEWORK_ADVISORIES) {
      expect(a.ghsa).toMatch(/^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$/);
      if (a.cve) expect(a.cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(a.summary.length).toBeGreaterThan(10);
      expect(a.ranges.length).toBeGreaterThan(0);
    }
  });
  it("encodes only parseable ranges whose patched version lies outside their own range", () => {
    for (const a of FRAMEWORK_ADVISORIES) {
      for (const { range, patched } of a.ranges) {
        expect(parseVersion(patched), `${a.ghsa} patched ${patched}`).not.toBeNull();
        expect(satisfies(patched, range), `${a.ghsa} ${range} contains its own fix ${patched}`).toBe(false);
        const lower = /^>=\s*([^\s,]+)/.exec(range)?.[1] ?? /^=\s*([^\s,]+)/.exec(range)?.[1];
        expect(lower && compareVersions(lower, patched), `${a.ghsa} ${range}`).toBeLessThan(0);
      }
    }
  });
  it("includes the advisories the task requires", () => {
    const ghsas = new Set(FRAMEWORK_ADVISORIES.map((a) => a.ghsa));
    for (const id of ["GHSA-f82v-jwr5-mffw", "GHSA-9qr9-h5gf-34mp", "GHSA-fv66-9v8q-g76r", "GHSA-fr5h-rqp8-mj6g", "GHSA-gp8f-8m3g-qvj9"]) {
      expect(ghsas.has(id), id).toBe(true);
    }
    expect(FRAMEWORK_ADVISORIES.find((a) => a.ghsa === "GHSA-f82v-jwr5-mffw")?.cve).toBe("CVE-2025-29927");
  });
});

describe("matchAdvisories", () => {
  const signals = { hasAppDir: true, middleware: [] as { file: string; callsAuth: boolean }[] };
  it("matches by range and reports the patched version for the matching range", () => {
    const hit = matchAdvisories("next", "14.2.24", signals).find((m) => m.advisory.ghsa === "GHSA-f82v-jwr5-mffw");
    expect(hit?.patched).toBe("14.2.25");
    expect(matchAdvisories("next", "14.2.25", signals).some((m) => m.advisory.ghsa === "GHSA-f82v-jwr5-mffw")).toBe(false);
    expect(matchAdvisories("next", "13.5.8", signals).find((m) => m.advisory.ghsa === "GHSA-f82v-jwr5-mffw")?.patched).toBe("13.5.9");
  });
  it("evaluates prerelease and canary versions", () => {
    const rsc = (v: string) => matchAdvisories("next", v, signals).some((m) => m.advisory.ghsa === "GHSA-9qr9-h5gf-34mp");
    expect(rsc("15.2.0-canary.5")).toBe(true);
    expect(rsc("14.3.0-canary.77")).toBe(true);
    expect(rsc("14.3.0-canary.76")).toBe(false);
    expect(rsc("15.0.4")).toBe(true);
    expect(rsc("15.0.5")).toBe(false);
    expect(rsc("14.2.5")).toBe(false);
  });
  it("skips advisories whose precondition is not met", () => {
    const noApp = { hasAppDir: false, middleware: [] };
    expect(matchAdvisories("next", "15.0.4", noApp).some((m) => m.advisory.ghsa === "GHSA-9qr9-h5gf-34mp")).toBe(false);
    expect(matchAdvisories("next", "14.2.10", noApp).some((m) => m.advisory.ghsa === "GHSA-7gfc-8cq8-jh5f")).toBe(false);
    const withMw = { hasAppDir: false, middleware: [{ file: "middleware.ts", callsAuth: false }] };
    expect(matchAdvisories("next", "14.2.10", withMw).some((m) => m.advisory.ghsa === "GHSA-7gfc-8cq8-jh5f")).toBe(true);
  });
  it("recommends a version that no encoded advisory still affects", () => {
    for (const v of ["13.4.0", "14.2.5", "15.0.4", "15.5.7", "16.0.0", "16.2.0"]) {
      const matches = matchAdvisories("next", v, signals);
      const fix = recommendedFix("next", v, matches, signals);
      expect(fix, v).toBeDefined();
      expect(matchAdvisories("next", fix ?? "0.0.0", signals), `${v} -> ${fix}`).toEqual([]);
      expect(parseVersion(fix ?? "")?.pre).toEqual([]);
      expect(compareVersions(fix ?? "0.0.0", v)).toBeGreaterThan(0);
    }
  });
});

describe("SUP-010 vulnerable framework versions", () => {
  const signals = (o: { app?: boolean; mw?: "none" | "plain" | "auth" } = {}) => ({
    hasAppDir: o.app ?? false,
    middleware: o.mw === undefined || o.mw === "none" ? [] : [{ file: "middleware.ts", callsAuth: o.mw === "auth" }],
  });
  const sev = (pkgName: string, version: string, ghsa: string, s: ReturnType<typeof signals>) =>
    matchAdvisories(pkgName, version, s).find((m) => m.advisory.ghsa === ghsa);

  it("reports one grouped finding per vulnerable version, ranked by its most serious advisory", async () => {
    const findings = sup010(await scan({
      "package.json": pkg({ next: "14.2.24" }),
      "package-lock.json": lockWith({ next: "14.2.24" }),
      "middleware.ts": "import { auth } from '@/auth';\nexport default auth((req) => { if (!req.auth) return Response.redirect('/login'); });\n",
    }));
    expect(findings).toHaveLength(1);
    const f = findings[0] as Finding;
    expect(f.severity).toBe("critical");
    expect(f.explanation).toContain("CVE-2025-29927");
    expect(f.explanation).toContain("14.2.25"); // that advisory's own fixed version
    // Same-major patch first (no breaking upgrade); anything only fixed on a newer major is named.
    expect(f.fix.config).toMatch(/^npm install next@14\.2\.\d+$/);
    expect(f.fix.summary).toMatch(/clears (all \d+|\d+ of \d+) .*without a major-version upgrade/);
    if (!/clears all/.test(f.fix.summary)) expect(f.fix.summary).toMatch(/newer major line/);
    expect(f.fix.summary.endsWith("..")).toBe(false);
    expect(f.cwe).toBe("CWE-1395");
    expect(f.evidence[0]).toMatchObject({ file: "package-lock.json", snippet: "next@14.2.24" });
    expect(f.fix.references.some((r) => r.endsWith("GHSA-f82v-jwr5-mffw"))).toBe(true);
  });

  it("rates CVE-2025-29927 by what the middleware does (critical / high / medium-low)", () => {
    const ghsa = "GHSA-f82v-jwr5-mffw";
    expect(sev("next", "14.2.24", ghsa, signals({ mw: "auth" }))?.severity).toBe("critical");
    expect(sev("next", "14.2.24", ghsa, signals({ mw: "plain" }))?.severity).toBe("high");
    const none = sev("next", "14.2.24", ghsa, signals());
    expect(none?.severity).toBe("medium");
    expect(none?.confidence).toBe("low");
  });

  it("treats a proxy.ts that calls auth like middleware", async () => {
    const findings = sup010(await scan({
      "package.json": pkg({ next: "15.2.2" }), "package-lock.json": lockWith({ next: "15.2.2" }),
      "src/proxy.ts": "import { getToken } from 'next-auth/jwt';\nexport async function proxy(req) { const t = await getToken({ req }); }\n",
    }));
    expect(byGhsa(findings, "GHSA-f82v-jwr5-mffw")?.severity).toBe("critical");
  });

  it("does not flag a patched Next.js", async () => {
    const findings = await scan({
      "package.json": pkg({ next: "16.3.6" }), "package-lock.json": lockWith({ next: "16.3.6" }),
      "app/page.tsx": "export default function P(){return null}", "middleware.ts": "export function middleware(){}",
    });
    expect(sup010(findings)).toEqual([]);
  });

  it("includes React2Shell only when an app/ directory exists", async () => {
    const files = { "package.json": pkg({ next: "15.0.4" }), "package-lock.json": lockWith({ next: "15.0.4" }) };
    expect(byGhsa(sup010(await scan(files)), "GHSA-9qr9-h5gf-34mp")).toBeUndefined();
    const f = byGhsa(sup010(await scan({ ...files, "app/layout.tsx": "export default function L(){return null}" })), "GHSA-9qr9-h5gf-34mp");
    expect(f?.severity).toBe("critical");
    expect(f?.explanation).toContain("CVE-2025-55182");
    expect(f?.explanation).toContain("15.0.5");
    expect(f?.fix.config).toMatch(/^npm install next@15\./);
  });

  it("detects the app dir under src/", async () => {
    const f = sup010(await scan({
      "package.json": pkg({ next: "15.1.0" }), "package-lock.json": lockWith({ next: "15.1.0" }), "src/app/page.tsx": "x",
    }));
    expect(byGhsa(f, "GHSA-9qr9-h5gf-34mp")).toBeDefined();
  });

  it("flags react-server-dom packages in the vulnerable range without needing app/", async () => {
    const f = sup010(await scan({
      "package.json": pkg({ "react-server-dom-webpack": "19.1.0" }), "package-lock.json": lockWith({ "react-server-dom-webpack": "19.1.0" }),
    }));
    const hit = byGhsa(f, "GHSA-fv66-9v8q-g76r");
    expect(hit?.severity).toBe("critical");
    expect(hit?.fix.config).toMatch(/^npm install react-server-dom-webpack@19\.1\.\d+$/);
    const safe = sup010(await scan({
      "package.json": pkg({ "react-server-dom-turbopack": "19.2.1" }), "package-lock.json": lockWith({ "react-server-dom-turbopack": "19.2.1" }),
    }));
    expect(byGhsa(safe, "GHSA-fv66-9v8q-g76r")).toBeUndefined();
  });

  it("uses an exactly pinned manifest version when there is no lockfile entry", async () => {
    expect(sev("next", "14.1.0", "GHSA-fr5h-rqp8-mj6g", signals())).toBeUndefined(); // needs app dir
    expect(sev("next", "14.1.0", "GHSA-fr5h-rqp8-mj6g", signals({ app: true }))?.severity).toBe("high");
    const withApp = sup010(await scan({ "package.json": pkg({ next: "14.1.0" }), "app/page.tsx": "x" }));
    const hit = byGhsa(withApp, "GHSA-fr5h-rqp8-mj6g");
    expect(hit?.evidence[0]?.file).toBe("package.json");
    expect(hit?.evidence[0]?.line).toBeGreaterThan(1);
    expect(hit?.fix.references.some((r) => r.endsWith("GHSA-fr5h-rqp8-mj6g"))).toBe(true);
    expect(sev("next", "14.1.0", "GHSA-fr5h-rqp8-mj6g", signals({ app: true }))?.patched).toBe("14.1.1");
  });

  it("never treats a caret range as the resolved version", async () => {
    const f = await scan({ "package.json": pkg({ next: "^14.1.0" }), "app/page.tsx": "x" });
    expect(sup010(f)).toEqual([]);
  });

  it("lets the lockfile win over a stale manifest pin and lists each advisory once", async () => {
    const f = sup010(await scan({
      "package.json": pkg({ next: "15.0.4" }), "package-lock.json": lockWith({ next: "15.0.4" }), "app/page.tsx": "x",
    }));
    expect(f).toHaveLength(1);
    const text = f[0]?.explanation ?? "";
    expect(text.split("GHSA-9qr9-h5gf-34mp").length - 1).toBe(1);
  });

  it("folds denial-of-service advisories into the same finding instead of separate cards", async () => {
    const f = sup010(await scan({
      "package.json": pkg({ next: "15.0.4" }), "package-lock.json": lockWith({ next: "15.0.4" }), "app/page.tsx": "x",
    }));
    expect(f).toHaveLength(1);
    expect(f[0]?.explanation).toMatch(/denial-of-service advisor/);
    expect(f[0]?.severity).toBe("critical"); // ranked by the worst advisory, not the DoS ones
  });
});
