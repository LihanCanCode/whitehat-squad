import type { Finding, HttpResult } from "../../core/types.js";
import { OWASP_HEADERS, headerFinding, make } from "./fixes.js";

const MIN_HSTS_SECONDS = 15_552_000; // 180 days
const SESSION_NAME = /sess|token|auth|jwt|\bsid\b|_sid$/i;
const JS_READABLE_OK = /csrf|xsrf/i;

/** Case-insensitive header lookup. */
export function header(res: HttpResult, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(res.headers)) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

/** Returns a short description of what is weak about a CSP, or null when it looks fine. */
export function cspWeakness(csp: string): string | null {
  const directives = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/);
    const name = tokens.shift()?.toLowerCase();
    if (name) directives.set(name, tokens.map((t) => t.toLowerCase()));
  }
  const script = directives.get("script-src") ?? directives.get("default-src");
  if (!script) return "it has no script-src or default-src directive, so scripts are not restricted";
  const hardened = script.some((t) => t.startsWith("'nonce-") || t.startsWith("'sha") || t === "'strict-dynamic'");
  const problems: string[] = [];
  if (script.includes("'unsafe-inline'") && !hardened) problems.push("'unsafe-inline'");
  if (script.includes("'unsafe-eval'")) problems.push("'unsafe-eval'");
  if (script.includes("*") || script.includes("http:")) problems.push("a wildcard source");
  return problems.length > 0 ? `script sources allow ${problems.join(", ")}` : null;
}

function hstsTooShort(value: string): boolean {
  const m = /max-age\s*=\s*"?(\d+)/i.exec(value);
  return !m || Number(m[1]) < MIN_HSTS_SECONDS;
}

export function headerFindings(res: HttpResult, target: URL): Finding[] {
  const url = res.url || target.href;
  const t = target.href;
  const out: Finding[] = [];
  const csp = header(res, "content-security-policy");

  if (csp === undefined) {
    out.push(headerFinding("WEB-L01", "csp", t, url, {
      severity: "medium",
      why: "Without a CSP, any injected script runs with full power, so one XSS bug becomes account takeover.",
    }));
  } else {
    const weakness = cspWeakness(csp);
    if (weakness) {
      out.push(headerFinding("WEB-L01", "csp", t, url, {
        severity: "low",
        weakness,
        why: "A weak CSP gives little protection against injected scripts.",
      }));
    }
  }

  if (target.protocol === "https:") {
    const hsts = header(res, "strict-transport-security");
    if (hsts === undefined) {
      out.push(headerFinding("WEB-L02", "hsts", t, url, {
        severity: "low",
        why: "Browsers may first connect over plain HTTP, where attackers on the network can downgrade or intercept the session.",
      }));
    } else if (hstsTooShort(hsts)) {
      out.push(headerFinding("WEB-L02", "hsts", t, url, {
        severity: "low",
        weakness: `max-age is under 180 days (${hsts})`,
        why: "A short HSTS lifetime lets browsers fall back to HTTP sooner.",
      }));
    }
  }

  const framed = header(res, "x-frame-options") !== undefined || /frame-ancestors/i.test(csp ?? "");
  if (!framed) {
    out.push(headerFinding("WEB-L03", "frame", t, url, {
      severity: "low",
      why: "Another site can embed yours in an invisible frame and trick users into clicking (clickjacking). Use X-Frame-Options or CSP frame-ancestors.",
    }));
  }

  if (header(res, "x-content-type-options")?.trim().toLowerCase() !== "nosniff") {
    out.push(headerFinding("WEB-L04", "nosniff", t, url, {
      severity: "low",
      why: "Browsers may guess file types and run uploaded content as script.",
    }));
  }
  if (header(res, "referrer-policy") === undefined) {
    out.push(headerFinding("WEB-L05", "referrer", t, url, {
      severity: "low",
      why: "Full URLs (which can contain tokens or ids) may be leaked to other sites through the Referer header.",
    }));
  }
  if (header(res, "permissions-policy") === undefined) {
    out.push(headerFinding("WEB-L06", "permissions", t, url, {
      severity: "low",
      why: "Embedded or injected content may request powerful browser features such as camera or location.",
    }));
  }
  return out;
}

interface CookieIssue {
  readonly name: string;
  readonly missing: readonly string[];
  readonly isSession: boolean;
}

function inspectCookie(raw: string, isHttps: boolean): CookieIssue | null {
  const [pair = "", ...attrs] = raw.split(";");
  // A pair with no "=" has no name: what is left would be the value itself, which must not be echoed.
  if (!pair.includes("=")) return null;
  const name = pair.split("=")[0]?.trim() ?? "";
  if (!name) return null;
  const flags = attrs.map((a) => a.trim().toLowerCase());
  const missing: string[] = [];
  if (isHttps && !flags.includes("secure")) missing.push("Secure");
  if (!flags.includes("httponly") && !JS_READABLE_OK.test(name)) missing.push("HttpOnly");
  if (!flags.some((f) => f.startsWith("samesite"))) missing.push("SameSite");
  return missing.length > 0 ? { name, missing, isSession: SESSION_NAME.test(name) } : null;
}

export function cookieFindings(res: HttpResult, target: URL): Finding[] {
  const issues = res.setCookies.map((c) => inspectCookie(c, target.protocol === "https:")).filter((c): c is CookieIssue => c !== null);
  if (issues.length === 0) return [];
  const escalate = issues.some((i) => i.isSession);
  const url = res.url || target.href;
  return [
    make({
      ruleId: "WEB-L08",
      title: "Cookies are missing security flags",
      severity: escalate ? "medium" : "low",
      explanation:
        "Some cookies are set without Secure, HttpOnly or SameSite. Without HttpOnly a script injected into the page can steal them; " +
        "without Secure they can travel over plain HTTP; without SameSite other sites can trigger authenticated requests (CSRF)." +
        (escalate ? " At least one looks like a session or auth cookie, which makes this more serious." : ""),
      evidence: issues.map((i) => ({ url, snippet: `Set-Cookie: ${i.name}=<redacted> (missing: ${i.missing.join(", ")})` })),
      fix: {
        summary: "Set Secure; HttpOnly; SameSite=Lax (or Strict) on every cookie, especially session cookies.",
        config: "Set-Cookie: <name>=<value>; Path=/; Secure; HttpOnly; SameSite=Lax\n\n// Express\nres.cookie(name, value, { secure: true, httpOnly: true, sameSite: 'lax' })",
        agentPrompt:
          `My site ${target.href} sets cookies without all of Secure, HttpOnly and SameSite (${issues.map((i) => i.name).join(", ")}). Find where these cookies are set in the code or auth library config and add secure: true, httpOnly: true, sameSite: 'lax'.`,
        references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies", OWASP_HEADERS],
      },
      target: target.href,
      cwe: "CWE-614",
    }),
  ];
}
