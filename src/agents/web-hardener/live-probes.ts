import type { Finding, SafeHttpClient, ScanContext } from "../../core/types.js";
import { OWASP_HEADERS, make } from "./fixes.js";
import { header } from "./live-headers.js";

export const PROBE_ORIGIN = "https://whsquad-probe.invalid";
export const NOT_FOUND_PATH = "/whsquad-probe-404-check";
export const MAX_MAPS = 3;
const SECRET_NAME = /SECRET|KEY|TOKEN|PASS|PWD|DATABASE_URL|DB_URL|PRIVATE|CREDENTIAL|DSN/i;
const MIN_SECRET_LENGTH = 6;
const HTML_START = /^\s*(?:<!doctype\s+html|<html|<head|<body|<\?xml)/i;

export interface Budgeted {
  readonly http: SafeHttpClient;
  readonly target: URL;
}

function absolute(target: URL, path: string): string {
  return new URL(path, target.origin).href;
}

/** WEB-L07: one GET with a hostile Origin; flag only echo + credentials. */
export async function probeCors({ http, target }: Budgeted): Promise<Finding[]> {
  const res = await http.get(target.href, { headers: { Origin: PROBE_ORIGIN } });
  const allow = header(res, "access-control-allow-origin");
  const creds = header(res, "access-control-allow-credentials");
  if (allow !== PROBE_ORIGIN || creds?.trim().toLowerCase() !== "true") return [];
  return [
    make({
      ruleId: "WEB-L07",
      title: "Server reflects any Origin and allows credentials (CORS)",
      severity: "high",
      explanation:
        "The server echoed an arbitrary, attacker-chosen Origin in Access-Control-Allow-Origin and also allowed credentials. " +
        "Any website a logged-in user visits can read authenticated responses from your API.",
      evidence: [{
        url: target.href,
        snippet: `Origin: ${PROBE_ORIGIN} -> access-control-allow-origin: ${allow}; access-control-allow-credentials: ${creds ?? ""}`,
      }],
      fix: {
        summary: "Only echo origins from a fixed allow-list; never reflect arbitrary Origin values with credentials.",
        config: "const allowed = new Set(['https://app.example.com']);\napp.use(cors({ origin: (o, cb) => cb(null, !!o && allowed.has(o)), credentials: true }));",
        agentPrompt:
          `My site ${target.href} reflects any Origin header in Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true. Replace it with a strict allow-list of my real frontend origins.`,
        references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", OWASP_HEADERS],
      },
      target: target.href,
      cwe: "CWE-942",
    }),
  ];
}

/** WEB-L09: reachable source maps that embed original sources. */
export async function probeSourceMaps(
  { http, target }: Budgeted,
  scripts: readonly { url: string; body: string }[],
  budget: number,
): Promise<Finding[]> {
  const limit = Math.min(MAX_MAPS, budget);
  const exposed: string[] = [];
  let used = 0;
  for (const script of scripts) {
    if (used >= limit) break;
    const m = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/.exec(script.body.slice(-600));
    const ref = m?.[1];
    if (!ref || ref.startsWith("data:")) continue;
    let mapUrl: URL;
    try {
      mapUrl = new URL(ref, script.url);
    } catch {
      continue;
    }
    if (mapUrl.origin !== target.origin) continue;
    used++;
    const res = await http.get(mapUrl.href, { maxBytes: 400_000 });
    if (res.status === 200 && /"sourcesContent"\s*:/.test(res.body)) exposed.push(mapUrl.href);
  }
  if (exposed.length === 0) return [];
  return [
    make({
      ruleId: "WEB-L09",
      title: "Source maps are publicly reachable",
      severity: "medium",
      explanation:
        "Your JavaScript points to .map files that anyone can download, and they contain your original source code. " +
        "Attackers can read your app logic, internal routes and any comments or keys left in code.",
      evidence: exposed.map((url) => ({ url, snippet: "source map reachable with sourcesContent (content not stored)" })),
      fix: {
        summary: "Stop publishing .map files (or restrict them to your error-tracking service).",
        config: "// next.config.js\nproductionBrowserSourceMaps: false\n// vite.config.ts\nbuild: { sourcemap: false }",
        agentPrompt:
          `The deployed site ${target.href} serves source maps (${exposed.join(", ")}). Disable production source maps in the build config and make sure .map files are not deployed.`,
        references: ["https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map", OWASP_HEADERS],
      },
      target: target.href,
      cwe: "CWE-540",
    }),
  ];
}

/** Parses KEY=VALUE lines of a dotenv file (values never leave this function except to registerSecret). */
export function parseEnv(body: string): { name: string; value: string }[] {
  const rows: { name: string; value: string }[] = [];
  for (const line of body.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    rows.push({ name: m[1] as string, value: (m[2] as string).trim().replace(/^(["'])(.*)\1$/, "$2") });
  }
  return rows;
}

interface FileProbe {
  readonly path: string;
  readonly title: string;
  readonly what: string;
  /** Returns severity + evidence snippet when the body has the real file's signature. */
  readonly check: (body: string, ctx: ScanContext) => { severity: "critical" | "high" | "medium"; snippet: string } | null;
}

function envCheck(body: string, ctx: ScanContext) {
  if (HTML_START.test(body)) return null;
  const rows = parseEnv(body);
  if (rows.length === 0) return null;
  const secretRows = rows.filter((r) => SECRET_NAME.test(r.name) && r.value.length >= MIN_SECRET_LENGTH);
  for (const r of secretRows) ctx.registerSecret(r.value);
  const names = rows.slice(0, 8).map((r) => r.name).join(", ");
  return {
    severity: secretRows.length > 0 ? ("critical" as const) : ("high" as const),
    snippet: `${rows.length} KEY=VALUE lines (names: ${names}); values withheld`,
  };
}

const FILE_PROBES: readonly FileProbe[] = [
  {
    path: "/.git/HEAD",
    title: "Git repository is publicly downloadable",
    what: "your .git folder, which lets anyone reconstruct your full source code and history (including old secrets)",
    check: (b) => (/^ref:\s*\S+/.test(b.trim()) && !HTML_START.test(b) ? { severity: "high", snippet: "HEAD file with 'ref:' signature" } : null),
  },
  { path: "/.env", title: "Environment file (.env) is publicly readable", what: "your .env file with configuration and likely API keys or passwords", check: envCheck },
  { path: "/.env.local", title: "Environment file (.env.local) is publicly readable", what: "your .env.local file with configuration and likely secrets", check: envCheck },
  {
    path: "/.DS_Store",
    title: "macOS .DS_Store file is publicly readable",
    what: "a macOS folder index that lists the names of files in your deployment directory",
    check: (b) => (b.slice(0, 16).includes("Bud1") ? { severity: "medium", snippet: ".DS_Store signature (Bud1)" } : null),
  },
  {
    path: "/wp-config.php.bak",
    title: "WordPress config backup is publicly readable",
    what: "a WordPress config backup containing database credentials",
    check: (b, ctx) => {
      if (HTML_START.test(b) || !/DB_NAME/.test(b) || !/define\s*\(/.test(b)) return null;
      const pw = /DB_PASSWORD['"]\s*,\s*['"]([^'"]+)['"]/.exec(b)?.[1];
      if (pw) ctx.registerSecret(pw);
      return { severity: "critical", snippet: "wp-config define() lines (values withheld)" };
    },
  },
  {
    path: "/phpinfo.php",
    title: "phpinfo() page is publicly reachable",
    what: "a phpinfo() page that reveals server paths, versions and environment variables",
    check: (b) => (/phpinfo\(\)|PHP Version\s+\d/.test(b) && /PHP Version/.test(b) ? { severity: "medium", snippet: "phpinfo() output" } : null),
  },
];

export const FILE_PROBE_COUNT = FILE_PROBES.length;

/** WEB-L10: GET sensitive paths; body is inspected and discarded. */
export async function probeSensitiveFiles(ctx: ScanContext, { http, target }: Budgeted): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const probe of FILE_PROBES) {
    const url = absolute(target, probe.path);
    const res = await http.get(url, { maxBytes: 64_000 });
    if (res.status !== 200) continue;
    const hit = probe.check(res.body, ctx);
    if (!hit) continue;
    out.push(
      make({
        ruleId: "WEB-L10",
        title: probe.title,
        severity: hit.severity,
        explanation: `Anyone on the internet can download ${probe.what}. This is a common vibe-coding deploy mistake (publishing the project folder as-is).`,
        evidence: [{ url, snippet: hit.snippet }],
        fix: {
          summary: `Remove ${probe.path} from the deployed site and block it at the server; rotate any secrets it contained.`,
          config:
            "# Netlify/Vercel: only deploy the build output folder (dist/ or .next/), never the project root\n" +
            "# nginx\nlocation ~ /\\.(git|env|DS_Store) { deny all; return 404; }",
          agentPrompt:
            `${url} is publicly reachable on my deployed site. Make sure only the build output is deployed (not the repo root), add a rule blocking dotfiles, delete this file from the server, and list every secret that may have been exposed so I can rotate it.`,
          references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information", OWASP_HEADERS],
        },
        target: target.href,
        cwe: "CWE-538",
      }),
    );
  }
  return out;
}

const ERROR_MARKERS: readonly { label: string; re: RegExp }[] = [
  { label: "Node.js stack trace", re: /\bat (?:Object|Module|Function|async)\.?[\w<>.]*\s*\(?[^\n]*:\d+:\d+/ },
  { label: "Python traceback", re: /Traceback \(most recent call last\)/ },
  { label: "Whoops/Laravel debug page", re: /Whoops[,!]|Ignition|Illuminate\\/ },
  { label: "Django DEBUG page", re: /DEBUG = True|Django.{0,30}DEBUG/ },
  { label: "Java stack trace", re: /\bat [\w.$]+\([\w]+\.java:\d+\)/ },
  { label: "Rails debug page", re: /ActionController::RoutingError|Rails\.root:/ },
];

/** WEB-L11: nonexistent path should not return stack traces. */
export async function probeVerboseErrors({ http, target }: Budgeted): Promise<Finding[]> {
  const url = absolute(target, NOT_FOUND_PATH);
  const res = await http.get(url, { maxBytes: 64_000 });
  const marker = ERROR_MARKERS.find((m) => m.re.test(res.body));
  if (!marker) return [];
  return [
    make({
      ruleId: "WEB-L11",
      title: "Server shows detailed error pages",
      severity: "medium",
      explanation:
        `A request to a page that does not exist returned a ${marker.label}. Debug output reveals file paths, framework versions and code, which helps attackers plan targeted attacks.`,
      evidence: [{ url, snippet: `HTTP ${res.status}: response contains a ${marker.label} (body not stored)` }],
      fix: {
        summary: "Turn off debug mode in production and return a generic error page.",
        config: "NODE_ENV=production\n# Django: DEBUG = False\n# Laravel: APP_DEBUG=false",
        agentPrompt:
          `Requesting ${url} on my deployed site returns a ${marker.label}. Disable debug/dev mode in production, add a generic 404/500 page, and log errors server-side only.`,
        references: ["https://owasp.org/www-community/Improper_Error_Handling", OWASP_HEADERS],
      },
      target: target.href,
      cwe: "CWE-209",
    }),
  ];
}
