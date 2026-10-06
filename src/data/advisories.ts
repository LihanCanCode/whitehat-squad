/**
 * Known-vulnerable framework releases, copied from GitHub's advisory database (GHSA) and
 * cross-checked against each advisory's own page. Only advisories whose id, ranges and first
 * patched versions were read back from the database are encoded here.
 *
 * Evidence (run on the snapshot date below):
 *   gh api "advisories?ecosystem=npm&affects=<package>&per_page=100" --paginate
 *   gh api advisories/<GHSA-id>
 * Range syntax is GitHub's ("= 19.2.0", ">= 13.0.0, < 13.5.9"); prereleases are ordered per semver.
 * Absence from this list does NOT mean a version is safe.
 */

export const ADVISORY_SNAPSHOT_DATE = "2026-10-05";

export type AdvisoryCategory = "rce" | "auth-bypass" | "ssrf" | "cache-poisoning" | "request-smuggling" | "dos";

/** Preconditions we can check from the repo; an advisory with an unmet `requires` is not reported. */
export type AdvisoryRequirement = "app-dir" | "middleware";

export interface AdvisoryRange {
  readonly range: string;
  /** First patched version for this range. */
  readonly patched: string;
}

export interface FrameworkAdvisory {
  readonly ghsa: string;
  readonly cve?: string;
  readonly package: string;
  /** Severity as published by GitHub. */
  readonly severity: "critical" | "high";
  readonly summary: string;
  readonly category: AdvisoryCategory;
  readonly ranges: readonly AdvisoryRange[];
  readonly requires?: AdvisoryRequirement;
  /** The exploit also needs a runtime condition we cannot see in the repo: reported with lower confidence. */
  readonly conditional?: string;
  /** Raise to critical when the middleware/proxy file performs authorization (CVE-2025-29927). */
  readonly escalateWithMiddlewareAuth?: boolean;
}

const r = (range: string, patched: string): AdvisoryRange => ({ range, patched });

const NEXT_RSC_RCE: readonly AdvisoryRange[] = [
  r(">= 14.3.0-canary.77, < 15.0.5", "15.0.5"),
  r(">= 15.1.0-canary.0, < 15.1.9", "15.1.9"),
  r(">= 15.2.0-canary.0, < 15.2.6", "15.2.6"),
  r(">= 15.3.0-canary.0, < 15.3.6", "15.3.6"),
  r(">= 15.4.0-canary.0, < 15.4.8", "15.4.8"),
  r(">= 15.5.0-canary.0, < 15.5.7", "15.5.7"),
  r(">= 16.0.0-canary.0, < 16.0.7", "16.0.7"),
];

const RSD_RCE: readonly AdvisoryRange[] = [
  r(">= 19.1.0, < 19.1.2", "19.1.2"),
  r("= 19.2.0", "19.2.1"),
  r("= 19.0.0", "19.0.1"),
];

const RSD_PACKAGES = ["react-server-dom-webpack", "react-server-dom-turbopack", "react-server-dom-parcel"] as const;

const NEXT_15_16 = (p15: string, p16: string, from15 = ">= 15.0.0"): readonly AdvisoryRange[] => [
  r(`${from15}, < ${p15}`, p15),
  r(`>= 16.0.0, < ${p16}`, p16),
];

export const FRAMEWORK_ADVISORIES: readonly FrameworkAdvisory[] = [
  // ---- critical ----
  {
    ghsa: "GHSA-f82v-jwr5-mffw", cve: "CVE-2025-29927", package: "next", severity: "critical", category: "auth-bypass",
    summary: "Authorization bypass in Next.js middleware via the x-middleware-subrequest header",
    ranges: [
      r(">= 12.0.0, < 12.3.5", "12.3.5"), r(">= 13.0.0, < 13.5.9", "13.5.9"),
      r(">= 14.0.0, < 14.2.25", "14.2.25"), r(">= 15.0.0, < 15.2.3", "15.2.3"),
    ],
    escalateWithMiddlewareAuth: true,
  },
  {
    ghsa: "GHSA-9qr9-h5gf-34mp", cve: "CVE-2025-55182", package: "next", severity: "critical", category: "rce",
    summary: "Unauthenticated remote code execution in the React Server Components flight protocol (React2Shell)",
    ranges: NEXT_RSC_RCE, requires: "app-dir",
  },
  ...RSD_PACKAGES.map((pkg): FrameworkAdvisory => ({
    ghsa: "GHSA-fv66-9v8q-g76r", cve: "CVE-2025-55182", package: pkg, severity: "critical", category: "rce",
    summary: "Unauthenticated remote code execution in React Server Components (React2Shell)",
    ranges: RSD_RCE,
  })),
  {
    ghsa: "GHSA-2xp9-vwfh-vxw4", package: "next", severity: "critical", category: "rce",
    summary: "Unauthenticated remote code execution in the Image Optimization API when AVIF files are used",
    ranges: [r(">= 10.0.0, < 15.5.24", "15.5.24"), r(">= 16.0.0, < 16.3.3", "16.3.3")],
    conditional: "it needs image optimization to process attacker-supplied AVIF files",
  },
  {
    ghsa: "GHSA-p293-qw3h-jr36", cve: "CVE-2026-75604", package: "next", severity: "critical", category: "rce",
    summary: "Unauthenticated remote code execution on Windows-hosted servers",
    ranges: [r(">= 13.4.0, < 15.5.24", "15.5.24"), r(">= 16.0.0, < 16.3.3", "16.3.3")],
    conditional: "it only affects servers hosted on a Windows filesystem",
  },
  {
    ghsa: "GHSA-vcvr-r3jv-pc5j", package: "next", severity: "critical", category: "rce",
    summary: "Remote code execution in next/og ImageResponse",
    ranges: [r(">= 16.2.0, < 16.3.6", "16.3.6")],
    conditional: "it needs the Node.js ImageResponse to render attacker-controlled values inside SVG",
  },

  // ---- high ----
  {
    ghsa: "GHSA-fr5h-rqp8-mj6g", cve: "CVE-2024-34351", package: "next", severity: "high", category: "ssrf",
    summary: "Server-Side Request Forgery in Server Actions",
    ranges: [r(">= 13.4.0, < 14.1.1", "14.1.1")],
    requires: "app-dir", conditional: "it needs a self-hosted deployment and a Server Action that redirects to a relative path",
  },
  {
    ghsa: "GHSA-89xv-2m56-2m9x", cve: "CVE-2026-64649", package: "next", severity: "high", category: "ssrf",
    summary: "Server-Side Request Forgery in Server Actions on custom servers",
    ranges: [r(">= 14.1.1, < 15.5.21", "15.5.21"), r(">= 16.0.0, < 16.2.11", "16.2.11")],
    requires: "app-dir", conditional: "it needs a custom server or deployment that does not pin the Host header",
  },
  {
    ghsa: "GHSA-p9j2-gv94-2wf4", cve: "CVE-2026-64645", package: "next", severity: "high", category: "ssrf",
    summary: "Server-Side Request Forgery in rewrites via an attacker-controlled destination hostname",
    ranges: [r(">= 12.0.0, < 15.5.21", "15.5.21"), r(">= 16.0.0, < 16.2.11", "16.2.11")],
    conditional: "it needs a rewrites() rule that builds its destination host from the request",
  },
  {
    ghsa: "GHSA-c4j6-fc7j-m34r", cve: "CVE-2026-44578", package: "next", severity: "high", category: "ssrf",
    summary: "Server-side request forgery in applications using WebSocket upgrades",
    ranges: [r(">= 13.4.13, < 15.5.16", "15.5.16"), r(">= 16.0.0, < 16.2.5", "16.2.5")],
    conditional: "it affects self-hosted deployments using the built-in Node.js server",
  },
  {
    ghsa: "GHSA-7gfc-8cq8-jh5f", cve: "CVE-2024-51479", package: "next", severity: "high", category: "auth-bypass",
    summary: "Authorization bypass when authorization is done in middleware based on the pathname",
    ranges: [r(">= 9.5.5, < 14.2.15", "14.2.15")], requires: "middleware",
  },
  {
    ghsa: "GHSA-6gpp-xcg3-4w24", cve: "CVE-2026-64642", package: "next", severity: "high", category: "auth-bypass",
    summary: "Middleware / Proxy bypass in App Router applications using Turbopack and a single locale",
    ranges: [r(">= 16.0.0, < 16.2.11", "16.2.11")], requires: "middleware",
    conditional: "it needs Turbopack and exactly one entry in i18n.locales",
  },
  {
    ghsa: "GHSA-26hh-7cqf-hhc6", cve: "CVE-2026-45109", package: "next", severity: "high", category: "auth-bypass",
    summary: "Middleware / Proxy bypass via segment-prefetch routes (incomplete fix follow-up)",
    ranges: [r(">= 15.2.0, < 15.5.18", "15.5.18"), r(">= 16.0.0, < 16.2.6", "16.2.6")], requires: "middleware",
  },
  {
    ghsa: "GHSA-267c-6grr-h53f", cve: "CVE-2026-44575", package: "next", severity: "high", category: "auth-bypass",
    summary: "Middleware / Proxy bypass in App Router applications via segment-prefetch routes",
    ranges: NEXT_15_16("15.5.16", "16.2.5", ">= 15.2.0"), requires: "middleware",
  },
  {
    ghsa: "GHSA-492v-c6pp-mqqv", cve: "CVE-2026-44574", package: "next", severity: "high", category: "auth-bypass",
    summary: "Middleware / Proxy bypass through dynamic route parameter injection",
    ranges: NEXT_15_16("15.5.16", "16.2.5", ">= 15.4.0"), requires: "middleware",
  },
  {
    ghsa: "GHSA-36qx-fr4f-26g5", cve: "CVE-2026-44573", package: "next", severity: "high", category: "auth-bypass",
    summary: "Middleware / Proxy bypass in Pages Router applications using i18n",
    ranges: NEXT_15_16("15.5.16", "16.2.5", ">= 12.2.0"), requires: "middleware",
    conditional: "it needs the Pages Router with i18n configured",
  },
  {
    ghsa: "GHSA-gp8f-8m3g-qvj9", cve: "CVE-2024-46982", package: "next", severity: "high", category: "cache-poisoning",
    summary: "Cache poisoning of non-dynamic server-side rendered routes in the Pages Router",
    ranges: [r(">= 13.5.1, < 13.5.7", "13.5.7"), r(">= 14.0.0, < 14.2.10", "14.2.10")],
    conditional: "it needs the Pages Router with non-dynamic server-side rendered routes behind a CDN",
  },
  {
    ghsa: "GHSA-67rr-84xm-4c7r", cve: "CVE-2025-49826", package: "next", severity: "high", category: "cache-poisoning",
    summary: "Cache poisoning that can cache a 204 response for static pages (denial of service)",
    ranges: [r(">= 15.0.4-canary.51, < 15.1.8", "15.1.8")],
  },
  {
    ghsa: "GHSA-77r5-gw3j-2mpf", cve: "CVE-2024-34350", package: "next", severity: "high", category: "request-smuggling",
    summary: "HTTP request smuggling (response queue poisoning) in affected rewrites setups",
    ranges: [r(">= 13.4.0, < 13.5.1", "13.5.1")],
    conditional: "it needs a rewrites() rule that proxies to an external backend",
  },

  // ---- denial of service (GitHub: high; we report these grouped at medium, availability only) ----
  {
    ghsa: "GHSA-fq54-2j52-jc42", cve: "CVE-2024-39693", package: "next", severity: "high", category: "dos",
    summary: "Denial of service condition", ranges: [r(">= 13.3.1, < 13.5.0", "13.5.0")],
  },
  {
    ghsa: "GHSA-mwv6-3258-q52c", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service with Server Components",
    ranges: [
      r(">= 13.3.0, < 14.2.34", "14.2.34"), r(">= 15.0.0-canary.0, < 15.0.6", "15.0.6"),
      r(">= 15.1.1-canary.0, < 15.1.10", "15.1.10"), r(">= 15.2.0-canary.0, < 15.2.7", "15.2.7"),
      r(">= 15.3.0-canary.0, < 15.3.7", "15.3.7"), r(">= 15.4.0-canary.0, < 15.4.9", "15.4.9"),
      r(">= 15.5.1-canary.0, < 15.5.8", "15.5.8"), r(">= 15.6.0-canary.0, < 15.6.0-canary.59", "15.6.0-canary.59"),
      r(">= 16.0.0-beta.0, < 16.0.9", "16.0.9"), r(">= 16.1.0-canary.0, < 16.1.0-canary.17", "16.1.0-canary.17"),
    ],
  },
  {
    ghsa: "GHSA-5j59-xgg2-r9c4", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service with Server Components (incomplete fix follow-up)",
    ranges: [
      r(">= 13.3.1-canary.0, < 14.2.35", "14.2.35"), r(">= 15.0.6, < 15.0.7", "15.0.7"),
      r(">= 15.1.10, < 15.1.11", "15.1.11"), r(">= 15.2.7, < 15.2.8", "15.2.8"),
      r(">= 15.3.7, < 15.3.8", "15.3.8"), r(">= 15.4.9, < 15.4.10", "15.4.10"),
      r(">= 15.5.8, < 15.5.9", "15.5.9"), r(">= 15.6.0-canary.59, < 15.6.0-canary.60", "15.6.0-canary.60"),
      r(">= 16.0.9, < 16.0.10", "16.0.10"), r(">= 16.1.0-canary.17, < 16.1.0-canary.19", "16.1.0-canary.19"),
    ],
  },
  {
    ghsa: "GHSA-h25m-26qc-wcjf", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "HTTP request deserialization can lead to DoS when using insecure React Server Components",
    ranges: [
      r(">= 13.0.0, < 15.0.8", "15.0.8"), r(">= 15.1.1-canary.0, < 15.1.12", "15.1.12"),
      r(">= 15.2.0-canary.0, < 15.2.9", "15.2.9"), r(">= 15.3.0-canary.0, < 15.3.9", "15.3.9"),
      r(">= 15.4.0-canary.0, < 15.4.11", "15.4.11"), r(">= 15.5.1-canary.0, < 15.5.10", "15.5.10"),
      r(">= 15.6.0-canary.0, < 15.6.0-canary.61", "15.6.0-canary.61"), r(">= 16.0.0-beta.0, < 16.0.11", "16.0.11"), r(">= 16.1.0-canary.0, < 16.1.5", "16.1.5"),
    ],
  },
  {
    ghsa: "GHSA-q4gf-8mx6-v5v3", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service with Server Components",
    ranges: [r(">= 13.0.0, < 15.5.15", "15.5.15"), r(">= 16.0.0-beta.0, < 16.2.3", "16.2.3")],
  },
  {
    ghsa: "GHSA-8h8q-6873-q5fj", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service with Server Components (CVE-2026-23870 upstream)",
    ranges: [r(">= 13.0.0, < 15.5.16", "15.5.16"), r(">= 16.0.0, < 16.2.5", "16.2.5")],
  },
  {
    ghsa: "GHSA-m99w-x7hq-7vfj", cve: "CVE-2026-64641", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service in App Router using Server Actions",
    ranges: [r(">= 13.0.0, < 15.5.21", "15.5.21"), r(">= 16.0.0, < 16.2.11", "16.2.11")],
  },
  {
    ghsa: "GHSA-mg66-mrh9-m8jx", cve: "CVE-2026-44579", package: "next", severity: "high", category: "dos", requires: "app-dir",
    summary: "Denial of service via connection exhaustion in applications using Cache Components",
    ranges: [r(">= 15.0.0, < 15.5.16", "15.5.16"), r(">= 16.0.0, < 16.2.5", "16.2.5")],
  },
];

export function advisoriesFor(pkg: string): readonly FrameworkAdvisory[] {
  return FRAMEWORK_ADVISORIES.filter((a) => a.package === pkg);
}

/** Package names that have at least one encoded advisory. */
export const ADVISORY_PACKAGES: ReadonlySet<string> = new Set(FRAMEWORK_ADVISORIES.map((a) => a.package));
