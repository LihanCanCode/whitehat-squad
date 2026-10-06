import { CWE, OWASP_TOP10, type FileCheck } from "./check.js";
import { matchBracket } from "./pytext.js";
import {
  argText, callsMatching, enclosingClass, hasFramework, isDevSettings, isExamplePath, isSettingsFile,
  rawArgText, rawMatches, stringValuesIn,
} from "./util.js";

const FLASK_DOCS = "https://flask.palletsprojects.com/en/stable/debugging/";
const DJANGO_DEPLOY = "https://docs.djangoproject.com/en/stable/howto/deployment/checklist/";

/** PY-001: Flask / Werkzeug debugger reachable in production. */
export function flaskDebug(fc: FileCheck): void {
  if (isExamplePath(fc.path) || !(hasFramework(fc, "flask") || /\bFlask\b/.test(fc.code))) return;
  const explain =
    "Flask's debug mode starts the Werkzeug debugger, which serves an interactive Python console in the browser. " +
    "Anyone who can reach your app and trigger any error page can run arbitrary code on your server, read your " +
    "environment variables and database passwords, and take the machine over.";
  const fix = {
    fixSummary: "Never hardcode debug. Read it from the environment (default off) and serve with gunicorn in production.",
    fixCode:
      'import os\n\nif __name__ == "__main__":\n    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")\n\n# production: gunicorn -w 4 "app:app"',
    references: [FLASK_DOCS, CWE(489), OWASP_TOP10],
  };
  for (const call of callsMatching(fc, /\.run\s*\(/)) {
    if (!/\bdebug\s*=\s*True\b/.test(argText(fc, call))) continue;
    fc.report({
      ruleId: "PY-001", offset: call.index, explanation: explain, ...fix,
      prompt: "app.run is started with debug=True. Replace it with debug=os.environ.get('FLASK_DEBUG') == '1' (off by default) and make sure production runs under gunicorn, not app.run.",
    });
  }
  for (const m of fc.code.matchAll(/\b\w+\.debug\s*=\s*True\b/g)) {
    fc.report({
      ruleId: "PY-001", offset: m.index, explanation: explain, ...fix,
      prompt: "The Flask debug flag is forced on. Drive it from an environment variable that defaults to off.",
    });
  }
  for (const s of fc.pt.strings) {
    if (s.value !== "FLASK_DEBUG") continue;
    const after = fc.pt.raw.slice(s.end, s.end + 40);
    if (/^\s*\]\s*=\s*["']?(?:1|true|on)\b/i.test(after) || /^\s*,\s*["']?(?:1|true|on)\b/i.test(after)) {
      fc.report({
        ruleId: "PY-001", offset: s.start, explanation: explain, ...fix,
        prompt: "FLASK_DEBUG is set to a truthy value in code. Remove it and set it only in your local shell.",
      });
    }
  }
}

/** PY-001 for env-style files: `.flaskenv` / committed `.env` with FLASK_DEBUG=1. */
export function flaskDebugEnvFile(text: string): { line: number; snippet: string } | null {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (/^\s*(?:export\s+)?FLASK_DEBUG\s*=\s*["']?(?:1|true|on)\b/i.test(line) ||
        /^\s*(?:export\s+)?FLASK_ENV\s*=\s*["']?development\b/i.test(line)) {
      return { line: i + 1, snippet: line.trim().slice(0, 200) };
    }
  }
  return null;
}

/** PY-002: Django DEBUG = True and ALLOWED_HOSTS = ['*']. */
export function djangoSettings(fc: FileCheck): void {
  if (!isSettingsFile(fc) || isDevSettings(fc.path)) return;
  for (const m of fc.code.matchAll(/^DEBUG\s*=\s*True\b/gm)) {
    fc.report({
      ruleId: "PY-002", offset: m.index,
      explanation:
        "Django is configured with DEBUG = True. On any error it shows a page with your settings, SQL queries, file paths " +
        "and environment values to whoever triggers it, and it keeps every SQL query in memory. Attackers use that leak to " +
        "find secrets and the next bug.",
      fixSummary: "Drive DEBUG from an environment variable that defaults to False.",
      fixCode: 'import os\n\nDEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"',
      prompt: "DEBUG is hardcoded to True. Read it from os.environ (default False) and make sure production never sets it.",
      references: [DJANGO_DEPLOY, CWE(489), OWASP_TOP10],
    });
  }
  for (const m of fc.code.matchAll(/^ALLOWED_HOSTS\s*=\s*[[(]/gm)) {
    const open = m.index + m[0].length - 1;
    const end = matchBracket(fc.code, open);
    if (end === -1 || !stringValuesIn(fc, open, end).includes("*")) continue;
    fc.report({
      ruleId: "PY-002", offset: m.index, severity: "medium", title: "Django ALLOWED_HOSTS accepts any host",
      explanation:
        "ALLOWED_HOSTS contains '*', so Django trusts whatever Host header the client sends. An attacker can request a " +
        "password reset with a forged Host header so the reset link in the victim's email points to the attacker's site, " +
        "and can poison caches that key on the host.",
      fixSummary: "List the real hostnames, optionally from the environment.",
      fixCode: 'ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "example.com").split(",")',
      prompt: "ALLOWED_HOSTS allows '*'. Replace it with the exact production hostnames (from an env var).",
      references: [DJANGO_DEPLOY, CWE(644), OWASP_TOP10],
    });
  }
}

const SECRET_ASSIGN = /\b(?:\w*SECRET_KEY|secret_key)\s*=\s*(?=[rbuRBU]{0,2}["'])/g;

/** PY-003: framework secret key committed as a string literal. */
export function hardcodedSecretKey(fc: FileCheck): void {
  if (!hasFramework(fc, "flask", "django") && !/\bSECRET_KEY\b/.test(fc.code)) return;
  for (const m of fc.code.matchAll(SECRET_ASSIGN)) {
    const lit = fc.pt.stringAt(m.index + m[0].length);
    if (!lit || lit.hasInterp || lit.value.trim() === "") continue;
    const insecure = /^django-insecure-/.test(lit.value);
    fc.report({
      ruleId: "PY-003", offset: m.index, secret: lit.value,
      explanation:
        `The ${insecure ? "Django 'django-insecure' placeholder " : ""}secret key is a literal string in your source code. ` +
        "Anyone who can read the repository (or a leaked copy of it) can forge session cookies and signed tokens, log in " +
        "as any user including admins, and craft password-reset links. Rotate it now: the committed value is burned.",
      fixSummary: "Load the key from the environment, fail fast when it is missing, and rotate the exposed value.",
      fixCode:
        'import os\n\nSECRET_KEY = os.environ["SECRET_KEY"]  # raises KeyError at startup if unset\n# generate: python -c "import secrets; print(secrets.token_urlsafe(64))"',
      prompt: "The secret key is hardcoded. Read it from os.environ['SECRET_KEY'] (no default), add it to the deployment secrets, and rotate the old value because it was committed.",
      references: ["https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY", CWE(798), OWASP_TOP10],
    });
  }
  for (const m of rawMatches(fc, /\.config\s*\[\s*["'](\w*SECRET_KEY)["']\s*\]\s*=\s*(?=[rbuRBU]{0,2}["'])/g)) {
    const lit = fc.pt.stringAt(m.index + m[0].length);
    if (!lit || lit.hasInterp || lit.value.trim() === "") continue;
    fc.report({
      ruleId: "PY-003", offset: m.index, secret: lit.value,
      explanation:
        "The Flask SECRET_KEY is a literal in source. Anyone who can read the repo can forge session cookies and signed " +
        "tokens and impersonate any user. Rotate the committed value.",
      fixSummary: "Load the key from the environment and rotate the exposed value.",
      fixCode: 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]',
      prompt: "app.config['SECRET_KEY'] is a literal. Read it from os.environ['SECRET_KEY'] and rotate the committed value.",
      references: ["https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY", CWE(798), OWASP_TOP10],
    });
  }
}

const TOGGLES = /\b(WTF_CSRF_ENABLED|CSRF_COOKIE_SECURE|SESSION_COOKIE_SECURE)\s*=\s*False\b/g;
const TOGGLE_ITEM = /\[\s*["'](WTF_CSRF_ENABLED|CSRF_COOKIE_SECURE|SESSION_COOKIE_SECURE)["']\s*\]\s*=\s*False\b/g;
const CSRF_DOCS = "https://docs.djangoproject.com/en/stable/ref/csrf/";
const WRITES = /\.(?:save|create|delete|update|bulk_create|bulk_update|add|add_all|commit|execute|insert_one|update_one|delete_one|get_or_create|update_or_create)\s*\(/;
const WEBHOOK_VERIFY = /signature|construct_event|hmac|verify_webhook|webhook_secret/i;

function csrfToggles(fc: FileCheck): void {
  const hits = [
    ...[...fc.code.matchAll(TOGGLES)].map((m) => ({ index: m.index, key: m[1] as string })),
    ...rawMatches(fc, TOGGLE_ITEM).map((m) => ({ index: m.index, key: m[1] as string })),
  ];
  for (const h of hits) {
    const cookie = h.key !== "WTF_CSRF_ENABLED";
    if (cookie && (isDevSettings(fc.path) || /test|dev|local/i.test(enclosingClass(fc, h.index)))) continue;
    if (!cookie && /test/i.test(enclosingClass(fc, h.index))) continue;
    fc.report({
      ruleId: "PY-004", offset: h.index,
      title: cookie ? `${h.key} is False` : "Flask-WTF CSRF protection is disabled",
      explanation: cookie
        ? `${h.key} = False lets the browser send your session/CSRF cookie over plain HTTP, where anyone on the same network ` +
          "(cafe Wi-Fi, a compromised router) can read it and hijack the session."
        : "WTF_CSRF_ENABLED = False turns off CSRF checks on every form. Any website a logged-in user visits can silently " +
          "submit those forms as them: change email or password, transfer money, delete data.",
      fixSummary: cookie ? "Set the cookie flag to True outside local development." : "Keep CSRF protection on and send the token with each form/request.",
      fixCode: cookie
        ? `${h.key} = True`
        : 'from flask_wtf.csrf import CSRFProtect\n\ncsrf = CSRFProtect(app)  # and include {{ csrf_token() }} in forms',
      prompt: `${h.key} is False. Set it to True for production settings (keep any local-dev override in a dev-only config).`,
      references: [CSRF_DOCS, CWE(352), OWASP_TOP10],
    });
  }
}

function csrfExemptViews(fc: FileCheck): void {
  for (const fn of fc.funcs) {
    if (!fn.decorators.some((d) => /^@\s*(?:\w+\.)*csrf_exempt\b/.test(d))) continue;
    const body = fc.code.slice(fn.bodyStart, fn.bodyEnd);
    const rawBody = fc.pt.raw.slice(fn.bodyStart, fn.bodyEnd);
    const writes = WRITES.test(body) || /request\.(?:POST|body)\b/.test(body) || /["']POST["']/.test(rawBody);
    if (!writes || WEBHOOK_VERIFY.test(rawBody) || /webhook/i.test(fn.name)) continue;
    fc.report({
      ruleId: "PY-004", offset: fn.start,
      title: `@csrf_exempt on state-changing view ${fn.name}`,
      explanation:
        `The view ${fn.name} writes data but is exempt from Django's CSRF check. Any web page a logged-in user visits can ` +
        "make their browser POST to it with their cookies attached and change or delete their data.",
      fixSummary: "Remove @csrf_exempt and send the CSRF token (X-CSRFToken header or {% csrf_token %}). For webhooks, verify a signature instead.",
      fixCode: "# remove @csrf_exempt\n# fetch('/api/x', {method: 'POST', headers: {'X-CSRFToken': getCookie('csrftoken')}, ...})",
      prompt: `Remove @csrf_exempt from ${fn.name} and have the client send the CSRF token. If it is a third-party webhook, verify the provider's signature instead.`,
      references: [CSRF_DOCS, CWE(352), OWASP_TOP10],
    });
  }
}

/** PY-004: CSRF exemptions and insecure cookie flags. */
export function csrfChecks(fc: FileCheck): void {
  csrfToggles(fc);
  csrfExemptViews(fc);
}

const CORS_DOCS = "https://fastapi.tiangolo.com/tutorial/cors/";

function corsReport(fc: FileCheck, offset: number, what: string): void {
  fc.report({
    ruleId: "PY-005", offset,
    explanation:
      `${what} Any website the user visits can then call your API with the user's cookies or tokens and read the ` +
      "responses, so a malicious page can read private data or act as the user.",
    fixSummary: "List the exact front-end origins instead of '*' when credentials are allowed.",
    fixCode:
      'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["https://app.example.com"],\n    allow_credentials=True,\n    allow_methods=["GET", "POST"],\n    allow_headers=["Authorization", "Content-Type"],\n)',
    prompt: "CORS allows any origin together with credentials. Replace the wildcard with the explicit list of front-end origins (from config).",
    references: [CORS_DOCS, CWE(942), OWASP_TOP10],
  });
}

/** PY-005: wildcard CORS with credentials (Starlette/FastAPI and Flask-CORS). */
export function corsChecks(fc: FileCheck): void {
  for (const call of callsMatching(fc, /\b(?:add_middleware|Middleware)\s*\(/)) {
    const code = argText(fc, call);
    if (!/\bCORSMiddleware\b/.test(code) || !/\ballow_credentials\s*=\s*True\b/.test(code)) continue;
    const origins = /\ballow_origins\s*=\s*[[(]/.exec(code);
    let wildcard = false;
    if (origins) {
      const open = call.open + 1 + origins.index + origins[0].length - 1;
      const end = matchBracket(fc.code, open);
      wildcard = end !== -1 && stringValuesIn(fc, open, end).includes("*");
    }
    const regex = /\ballow_origin_regex\s*=\s*(?=["'])/.exec(code);
    if (regex) {
      const lit = fc.pt.stringAt(call.open + 1 + regex.index + regex[0].length);
      wildcard = wildcard || (lit !== undefined && /^\.\*$|^\.\+$/.test(lit.value));
    }
    if (wildcard) corsReport(fc, call.index, "CORSMiddleware allows every origin (\"*\") and also allow_credentials=True.");
  }
  if (!/\bflask_cors\b/.test(fc.pt.raw)) return;
  for (const call of callsMatching(fc, /\bCORS\s*\(/)) {
    const code = argText(fc, call);
    if (!/\bsupports_credentials\s*=\s*True\b/.test(code)) continue;
    const raw = rawArgText(fc, call);
    const wildcard = stringValuesIn(fc, call.open, call.end).some((v) => v === "*" || v === ".*");
    const namedOrigins = /\borigins\b/.test(raw);
    if (wildcard || !namedOrigins) corsReport(fc, call.index, "Flask-CORS is set to supports_credentials=True with the default or wildcard origin.");
  }
}
