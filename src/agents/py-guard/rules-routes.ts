import { CWE, OWASP_TOP10, type FileCheck } from "./check.js";
import type { PyFunction } from "./scope.js";
import { hasFramework } from "./util.js";

const ROUTE_DECO = /^@\s*([\w]+)\s*\.\s*(route|get|post|put|patch|delete|api_route)\s*\(/;
const DB_TOUCH =
  /\.(?:query|objects|table|scalars?|execute|executemany|commit|add_all|bulk_create|insert_one|find_one|update_one|delete_one|bulk_save_objects)\b|\b(?:session|db|database|sess)\s*\.\s*(?:add|delete|merge|get|refresh|flush)\s*\(/;
const PUBLIC_ROUTE =
  /login|logout|log_in|register|signup|sign_up|signin|sign_in|health|ping|docs|openapi|redoc|metrics|webhook|callback|oauth|forgot|reset_password|verify_email|favicon|robots/i;
const PUBLIC_PATH = /["'][^"']*(?:\/(?:login|logout|register|signup|signin|auth|token|health|healthz|ping|docs|openapi\.json|redoc|metrics|webhook|callback|oauth)\b)[^"']*["']/i;
const AUTH_NAME = /auth|user|token|jwt|current|verify|require|permission|admin|login|api_?key|principal|bearer|oauth|scheme|credential|role|scope/i;
const FLASK_AUTH_DECORATOR = /login|auth|jwt|token|permission|role|admin|protect|secure|require|verify/i;
const FLASK_AUTH_BODY =
  /\bcurrent_user\b|get_jwt_identity|\bget_jwt\s*\(|\bg\s*\.\s*user\b|\bverify_jwt|abort\s*\(\s*40[13]\b|is_authenticated|\bAuthorization\b|session\s*\[\s*["'](?:user|uid|user_id|email)["']|session\.get\s*\(\s*["'](?:user|uid|user_id)/;

export function hasProjectAuthDependency(raw: string): boolean {
  return /\bFastAPI\s*\([^)]*\bdependencies\s*=\s*\[\s*(?:Depends|Security)/s.test(raw) ||
    /\binclude_router\s*\([^)]*\bdependencies\s*=\s*\[\s*(?:Depends|Security)/s.test(raw);
}

function rawDecorators(fc: FileCheck, fn: PyFunction): string {
  return fc.pt.raw.slice(fn.start, fn.defStart);
}

function fastapiAuthenticated(fn: PyFunction, rawDeco: string, routerGuarded: ReadonlySet<string>, owner: string): boolean {
  if (routerGuarded.has(owner)) return true;
  if (/\bdependencies\s*=\s*\[\s*(?:Depends|Security)/.test(rawDeco)) return true;
  if (/\bSecurity\s*\(|\bHTTPBearer\b|\bOAuth2\w*Bearer\b|\bAPIKey(?:Header|Query|Cookie)\b/.test(fn.params)) return true;
  if (/\bcurrent_(?:active_)?user\b|\bcurrent_account\b|\bauthenticated_user\b/.test(fn.params)) return true;
  for (const m of fn.params.matchAll(/\bDepends\s*\(\s*([\w.]+)/g)) {
    if (AUTH_NAME.test(m[1] as string)) return true;
  }
  return false;
}

function flaskAuthenticated(fc: FileCheck, fn: PyFunction): boolean {
  const others = fn.decorators.filter((d) => !ROUTE_DECO.test(d));
  if (others.some((d) => FLASK_AUTH_DECORATOR.test(d))) return true;
  const body = fc.pt.raw.slice(fn.bodyStart, fn.bodyEnd);
  return FLASK_AUTH_BODY.test(body);
}

function routerGuardedNames(fc: FileCheck): Set<string> {
  const names = new Set<string>();
  for (const m of fc.pt.raw.matchAll(/^(\w+)\s*=\s*(?:fastapi\.)?APIRouter\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)/gm)) {
    if (/\bdependencies\s*=\s*\[\s*(?:Depends|Security)/.test(m[2] as string)) names.add(m[1] as string);
  }
  return names;
}

function fileHasAuthHook(fc: FileCheck): boolean {
  return /\bbefore_request\b[\s\S]{0,600}(?:login|auth|token|jwt|current_user|abort\s*\(\s*40[13])/i.test(fc.pt.raw) ||
    /@\s*\w+\.middleware\s*\(\s*["']http["']\s*\)[\s\S]{0,800}(?:Authorization|token|jwt|401|403)/i.test(fc.pt.raw);
}

/** PY-012: data-touching routes with no authentication. */
export function unauthenticatedRoutes(fc: FileCheck, projectHasAppDeps: boolean): void {
  const fastapi = hasFramework(fc, "fastapi") && /\b(?:fastapi|starlette)\b/.test(fc.pt.raw);
  const flask = !fastapi && /^[ \t]*(?:from|import)[ \t]+flask\b/m.test(fc.pt.raw);
  if (!fastapi && !flask) return;
  if (fileHasAuthHook(fc)) return;
  const guarded = routerGuardedNames(fc);
  for (const fn of fc.funcs) {
    const route = fn.decorators.map((d) => ROUTE_DECO.exec(d)).find((m) => m !== null);
    if (!route) continue;
    const body = fc.code.slice(fn.bodyStart, fn.bodyEnd);
    if (!DB_TOUCH.test(body) || PUBLIC_ROUTE.test(fn.name)) continue;
    const rawDeco = rawDecorators(fc, fn);
    if (PUBLIC_PATH.test(rawDeco)) continue;
    const authed = fastapi
      ? projectHasAppDeps || fastapiAuthenticated(fn, rawDeco, guarded, route[1] as string)
      : flaskAuthenticated(fc, fn);
    if (authed) continue;
    const kind = fastapi ? "FastAPI" : "Flask";
    fc.report({
      ruleId: "PY-012", offset: fn.start, confidence: "medium",
      title: `${kind} route ${fn.name} reads or writes the database without authentication`,
      explanation:
        `The route ${fn.name} touches the database but nothing in its signature or decorators checks who is calling. ` +
        "Anyone on the internet can request it and read or change data, including other users' records. (If authentication " +
        "is enforced by a gateway or middleware this scanner cannot see, mark this line with # whsquad-ignore PY-012.)",
      fixSummary: fastapi
        ? "Require an authenticated user dependency and filter data by that user."
        : "Protect the route with a login/JWT decorator and filter data by the authenticated user.",
      fixCode: fastapi
        ? '@router.get("/items")\ndef list_items(\n    db: Session = Depends(get_db),\n    current_user: User = Depends(get_current_user),\n):\n    return db.query(Item).filter(Item.owner_id == current_user.id).all()'
        : '@app.route("/items")\n@login_required  # or @jwt_required()\ndef list_items():\n    return Item.query.filter_by(owner_id=current_user.id).all()',
      prompt: `Route ${fn.name} accesses the database with no auth. Add ${fastapi ? "Depends(get_current_user)" : "@login_required / @jwt_required()"} and scope every query to the authenticated user. If the route is intentionally public, add a comment explaining why.`,
      references: fastapi
        ? ["https://fastapi.tiangolo.com/tutorial/security/", CWE(306), OWASP_TOP10]
        : ["https://flask-login.readthedocs.io/en/latest/#flask_login.login_required", CWE(306), OWASP_TOP10],
    });
  }
}
