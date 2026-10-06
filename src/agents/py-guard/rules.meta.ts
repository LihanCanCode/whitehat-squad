import type { RuleMeta } from "../../rules/types.js";

const AGENT = "py-guard";
const MODES = ["static"] as const;

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
export const RULES: readonly RuleMeta[] = [
  {
    id: "PY-001", agent: AGENT, title: "Flask debug mode enabled", severity: "high", cwe: "CWE-489", owasp: "A05", modes: MODES,
    summary: "Flask is started with debug=True (or FLASK_DEBUG=1 / app.debug = True). The Werkzeug debugger serves an interactive Python console in the browser; anyone who can reach the app and get an error page can run code on the server.",
    fix: "Never hardcode debug. Read it from the environment (default off) and run production under gunicorn/uwsgi instead of app.run().",
    tags: ["python", "flask", "rce"],
  },
  {
    id: "PY-002", agent: AGENT, title: "Django DEBUG = True or ALLOWED_HOSTS wildcard", severity: "high", cwe: "CWE-489", owasp: "A05", modes: MODES,
    summary: "A Django settings file sets DEBUG = True unconditionally (or ALLOWED_HOSTS = ['*']). Debug pages leak settings, SQL, file paths and environment values; a wildcard host list enables Host-header poisoning such as password-reset link hijacking.",
    fix: "Drive DEBUG from an environment variable that defaults to False and list real hostnames in ALLOWED_HOSTS.",
    tags: ["python", "django", "config"],
  },
  {
    id: "PY-003", agent: AGENT, title: "Hardcoded framework secret key", severity: "high", cwe: "CWE-798", owasp: "A02", modes: MODES,
    summary: "Flask's secret_key / SECRET_KEY or Django's SECRET_KEY is a string literal in source. Whoever can read the repository can forge session cookies, signed tokens and password-reset links, which is full account takeover.",
    fix: "Load the key from an environment variable or secret manager, fail startup if it is missing, and rotate the exposed key.",
    tags: ["python", "secrets"],
  },
  {
    id: "PY-004", agent: AGENT, title: "CSRF protection or secure cookies disabled", severity: "medium", cwe: "CWE-352", owasp: "A01", modes: MODES,
    summary: "CSRF protection is switched off (@csrf_exempt on a state-changing view, WTF_CSRF_ENABLED = False) or session/CSRF cookies are allowed over plain HTTP. A malicious page can make a logged-in user's browser perform actions or leak cookies.",
    fix: "Remove the exemption and send the CSRF token with each request; set *_COOKIE_SECURE = True outside local development.",
    tags: ["python", "csrf"],
  },
  {
    id: "PY-005", agent: AGENT, title: "CORS allows any origin with credentials", severity: "high", cwe: "CWE-942", owasp: "A05", modes: MODES,
    summary: "CORS is configured with a wildcard (or default) origin together with credentials. Any website a user visits can then call the API as that user and read the responses.",
    fix: "List the exact front-end origins in allow_origins / origins instead of '*'.",
    tags: ["python", "cors", "fastapi", "flask"],
  },
  {
    id: "PY-006", agent: AGENT, title: "SQL built from strings (SQL injection)", severity: "high", cwe: "CWE-89", owasp: "A03", modes: MODES,
    summary: "A SQL statement is assembled with an f-string, %, + or .format() and passed to execute()/text()/raw()/extra(). An attacker who controls any interpolated value can read, modify or delete the whole database. Critical when the value comes straight from request input.",
    fix: "Pass values as bound parameters (execute('... %s', (x,)) or text('... :x') with a dict) and never format them into the SQL text.",
    tags: ["python", "sql", "injection"],
  },
  {
    id: "PY-007", agent: AGENT, title: "OS command built from strings (command injection)", severity: "high", cwe: "CWE-78", owasp: "A03", modes: MODES,
    summary: "A shell command is built from non-literal data and run with shell=True, os.system or os.popen. Shell metacharacters in the data (; | $()) run arbitrary commands as the server user. Critical when the data comes from request input.",
    fix: "Pass an argument list without shell=True (subprocess.run(['cmd', arg], check=True)) and validate arg against an allowlist.",
    tags: ["python", "injection", "rce"],
  },
  {
    id: "PY-008", agent: AGENT, title: "Unsafe deserialization", severity: "high", cwe: "CWE-502", owasp: "A08", modes: MODES,
    summary: "pickle/dill/marshal loads attacker-influenced bytes, or yaml.load is used without a safe loader. Crafted input executes arbitrary code during deserialization.",
    fix: "Use JSON for untrusted data, and yaml.safe_load instead of yaml.load. Never unpickle data from users or uploads.",
    tags: ["python", "deserialization", "rce"],
  },
  {
    id: "PY-009", agent: AGENT, title: "eval/exec on dynamic input", severity: "medium", cwe: "CWE-95", owasp: "A03", modes: MODES,
    summary: "eval() or exec() runs a non-literal string. If any part of it comes from a request, a user runs arbitrary Python on your server (critical); otherwise it is a fragile pattern that invites that bug later.",
    fix: "Use ast.literal_eval for data, json.loads for JSON, and an explicit dispatch table for operations.",
    tags: ["python", "rce"],
  },
  {
    id: "PY-010", agent: AGENT, title: "Server-side request forgery from user-controlled URL", severity: "high", cwe: "CWE-918", owasp: "A10", modes: MODES,
    summary: "requests/httpx/urllib fetches a URL taken from request input with no host allowlist. Attackers point it at cloud metadata (169.254.169.254) or internal services and read credentials or private data through your server.",
    fix: "Parse the URL, require https, and check the hostname against an explicit allowlist before fetching.",
    tags: ["python", "ssrf"],
  },
  {
    id: "PY-011", agent: AGENT, title: "Path traversal from user-controlled file path", severity: "high", cwe: "CWE-22", owasp: "A01", modes: MODES,
    summary: "open()/send_file()/FileResponse()/send_from_directory() receives a path built from request input without sanitising it. ../../ sequences let attackers read any file the server can, such as .env, SSH keys or source code.",
    fix: "Use secure_filename or os.path.basename, resolve the final path and confirm it stays inside the intended directory.",
    tags: ["python", "path-traversal"],
  },
  {
    id: "PY-012", agent: AGENT, title: "Data-touching route without authentication", severity: "high", cwe: "CWE-306", owasp: "A01", modes: MODES,
    summary: "A FastAPI or Flask route reads or writes the database but has no auth dependency/decorator. Anyone on the internet can call it and read or change other users' data. Reported at medium confidence because auth may be enforced by middleware this scanner cannot see.",
    fix: "Add Depends(get_current_user) (FastAPI) or @login_required/@jwt_required (Flask) and filter data by the authenticated user.",
    tags: ["python", "auth", "fastapi", "flask"],
  },
  {
    id: "PY-013", agent: AGENT, title: "Mass assignment from request body", severity: "medium", cwe: "CWE-915", owasp: "A04", modes: MODES,
    summary: "A request body is splatted straight into a model (Model(**request.json), **payload.dict()) or a DRF serializer exposes fields = '__all__'. Users can set fields they should not, such as is_admin, role or owner_id.",
    fix: "Declare an explicit allowlist of writable fields (a Pydantic input schema or serializer fields tuple).",
    tags: ["python", "mass-assignment"],
  },
  {
    id: "PY-014", agent: AGENT, title: "JWT verification disabled or hardcoded secret", severity: "high", cwe: "CWE-347", owasp: "A02", modes: MODES,
    summary: "jwt.decode runs with verify_signature False or algorithms ['none'], or tokens are signed with a literal secret. Attackers can mint tokens for any user (critical when verification is off).",
    fix: "Always verify with a fixed algorithm list (['HS256'] or ['RS256']) and a secret from the environment.",
    tags: ["python", "jwt", "auth"],
  },
  {
    id: "PY-015", agent: AGENT, title: "Passwords hashed with a fast hash", severity: "high", cwe: "CWE-916", owasp: "A02", modes: MODES,
    summary: "A password is hashed with hashlib md5/sha1/sha256. These hashes are built for speed, so a leaked database is cracked at billions of guesses per second.",
    fix: "Use a slow password hash such as argon2-cffi, bcrypt, or werkzeug.security.generate_password_hash / django.contrib.auth.hashers.make_password.",
    tags: ["python", "passwords"],
  },
];
