import { CWE, OWASP_TOP10, type FileCheck } from "./check.js";
import { judge } from "./rules-injection.js";
import { argText, callsMatching, enclosingCallOpen, rawArgText, rawMatches, trimStart } from "./util.js";

function bodyOf(fc: FileCheck, offset: number): string {
  const fn = fc.fn(offset);
  return fn ? fc.code.slice(fn.bodyStart, fn.bodyEnd) : fc.code;
}

const PICKLE = /\b(?:pickle|cPickle|_pickle|dill|cloudpickle|marshal|joblib)\s*\.\s*(?:loads?|Unpickler)\s*\(/;
const YAML_LOAD = /\byaml\s*\.\s*(?:load|load_all)\s*\(/;
const SAFE_LOADER = /\bLoader\s*=\s*(?:yaml\.)?C?SafeLoader\b|,\s*(?:yaml\.)?C?SafeLoader\s*\)?$/;

/** PY-008: pickle/yaml deserialization of untrusted data. */
export function unsafeDeserialization(fc: FileCheck): void {
  for (const call of callsMatching(fc, PICKLE)) {
    const first = call.args[0];
    if (!first || !judge(fc, first, call.index).tainted) continue;
    fc.report({
      ruleId: "PY-008", offset: call.index, severity: "high",
      explanation:
        "Data from the HTTP request or an uploaded file is passed to a pickle-style loader. Unpickling executes code chosen " +
        "by whoever built the bytes, so any visitor can run commands on your server with one crafted request.",
      fixSummary: "Exchange data as JSON (validated with a schema). Never unpickle anything a user can influence.",
      fixCode: "import json\n\ndata = json.loads(request.get_data())  # then validate with pydantic/marshmallow",
      prompt: "Request or upload data is deserialized with pickle/dill/marshal. Replace it with JSON plus schema validation; if a model file must be loaded, only load files you generated and verify a checksum.",
      references: ["https://docs.python.org/3/library/pickle.html#restricting-globals", CWE(502), OWASP_TOP10],
    });
  }
  for (const call of callsMatching(fc, YAML_LOAD)) {
    if (SAFE_LOADER.test(argText(fc, call).trim())) continue;
    fc.report({
      ruleId: "PY-008", offset: call.index, title: "yaml.load without a safe loader",
      explanation:
        "yaml.load can construct arbitrary Python objects, so a crafted YAML document (an upload, a config a user can edit, " +
        "an API body) runs code on your server when it is parsed.",
      fixSummary: "Use yaml.safe_load, or pass Loader=yaml.SafeLoader.",
      fixCode: "import yaml\n\nconfig = yaml.safe_load(stream)",
      prompt: "Replace yaml.load(...) with yaml.safe_load(...) (or add Loader=yaml.SafeLoader).",
      references: ["https://pyyaml.org/wiki/PyYAMLDocumentation", CWE(502), OWASP_TOP10],
    });
  }
}

const HTTP_CALL = /\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|delete|head|options|request|stream)\s*\(|(?<![.\w])urlopen\s*\(|\burllib\.request\.(?:urlopen|urlretrieve)\s*\(|\bhttp\.client\.\w+\s*\(/;
const HOST_GUARD = /\b(?:urlparse|urlsplit)\b[\s\S]*\b(?:hostname|netloc)\b[\s\S]*(?:allow|white|trusted|ALLOW|WHITE|TRUSTED)|\bipaddress\b[\s\S]*\bis_(?:private|loopback|link_local)\b|(?:allow|white|trusted)\w*host/i;
const FIXED_HOST = /^https?:\/\/[^/{}\s]+(?:\/|$)/i;

/** PY-010: outbound request to a user-controlled URL. */
export function ssrf(fc: FileCheck): void {
  for (const call of callsMatching(fc, HTTP_CALL)) {
    const isRequestMethod = /\.\s*(?:request|stream)\s*\($/.test(fc.code.slice(call.index, call.open + 1));
    const urlArg = isRequestMethod ? (call.args[1] ?? call.args[0]) : call.args[0];
    if (!urlArg) continue;
    const start = trimStart(fc.code, urlArg.start, urlArg.end);
    const lit = fc.pt.stringAt(start);
    if (lit && lit.start === start && FIXED_HOST.test(lit.value)) continue; // scheme + host are fixed, only the path varies
    if (!judge(fc, urlArg, call.index).tainted) continue;
    if (HOST_GUARD.test(bodyOf(fc, call.index))) continue;
    fc.report({
      ruleId: "PY-010", offset: call.index,
      explanation:
        "The server fetches a URL that comes from the request. An attacker submits http://169.254.169.254/ (the cloud " +
        "metadata service) or an internal address and your server returns the cloud credentials or private data it " +
        "finds there. This is the classic route from a web bug to a full cloud account takeover.",
      fixSummary: "Parse the URL, require https, and only allow hostnames from an explicit allowlist.",
      fixCode:
        'from urllib.parse import urlparse\n\nALLOWED_HOSTS = {"api.example.com"}\n\nparsed = urlparse(url)\nif parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:\n    abort(400)\nresp = requests.get(url, timeout=5, allow_redirects=False)',
      prompt: "This outbound request uses a URL from user input. Validate scheme == https and hostname against an allowlist before fetching, disable redirects and set a timeout.",
      references: ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", CWE(918), OWASP_TOP10],
    });
  }
}

const FILE_CALL = /(?<![.\w])open\s*\(|\bsend_file\s*\(|\bFileResponse\s*\(|\bsend_from_directory\s*\(/;
const PATH_SANITIZER = /\b(?:secure_filename|basename|safe_join)\s*\(/;
const CONTAINMENT = /\b(?:realpath|resolve|abspath)\b[\s\S]*\b(?:startswith|is_relative_to|commonpath|commonprefix)\b/;

/** PY-011: user-controlled file paths. */
export function pathTraversal(fc: FileCheck): void {
  for (const call of callsMatching(fc, FILE_CALL)) {
    const first = call.args[0];
    if (!first) continue;
    const text = fc.code.slice(first.start, first.end);
    if (PATH_SANITIZER.test(text)) continue;
    const verdict = judge(fc, first, call.index);
    if (!verdict.tainted) continue; // send_from_directory: only the directory (first arg) is checked, Flask guards the filename
    if (CONTAINMENT.test(bodyOf(fc, call.index))) continue;
    fc.report({
      ruleId: "PY-011", offset: call.index,
      explanation:
        "A file is opened or served using a path built from request input. An attacker sends ../../.env or " +
        "/etc/passwd and downloads (or overwrites) any file the server can read: secrets, source code, SSH keys, other " +
        "users' uploads.",
      fixSummary: "Reduce the input to a bare filename and confirm the resolved path stays inside the intended folder.",
      fixCode:
        'from pathlib import Path\nfrom werkzeug.utils import secure_filename\n\nBASE = Path("uploads").resolve()\npath = (BASE / secure_filename(name)).resolve()\nif not path.is_relative_to(BASE):\n    abort(400)',
      prompt: "This file path is built from request input. Apply secure_filename/os.path.basename and verify Path(...).resolve().is_relative_to(BASE_DIR) before opening or serving it.",
      references: ["https://owasp.org/www-community/attacks/Path_Traversal", CWE(22), OWASP_TOP10],
    });
  }
}

const SPLAT_SOURCE =
  /\*\*\s*(?:request\s*\.\s*(?:json|form|args|values|POST|data)\b|(?:await\s+)?request\s*\.\s*(?:get_json|json)\s*\(\s*\)|(\w+)\s*\.\s*(?:dict|model_dump)\s*\(\s*\))/g;
const WRITE_CALLEE = /(?:\b[A-Z]\w*|\.(?:create|update|update_or_create|get_or_create|insert|insert_one|bulk_create|add|setattr))\s*$/;

/** PY-013: request bodies splatted into ORM writes, and DRF `fields = '__all__'`. */
export function massAssignment(fc: FileCheck): void {
  for (const m of fc.code.matchAll(SPLAT_SOURCE)) {
    const open = enclosingCallOpen(fc.code, m.index);
    if (open === -1 || !WRITE_CALLEE.test(fc.code.slice(Math.max(0, open - 60), open))) continue;
    const viaSchema = m[1] !== undefined;
    if (viaSchema && !fc.tainted(fc.fn(m.index)).has(m[1] as string)) continue;
    fc.report({
      ruleId: "PY-013", offset: m.index, confidence: viaSchema ? "medium" : "high",
      explanation:
        "The whole request body is passed into a database model. A caller can add extra fields such as is_admin, role, " +
        "balance or owner_id to the JSON and the ORM will happily set them, so a normal user can promote themselves or " +
        "take over someone else's records.",
      fixSummary: "Accept only an explicit allowlist of fields (a Pydantic input model without privileged fields).",
      fixCode:
        'class UserCreate(BaseModel):          # only what a client may set\n    email: str\n    name: str\n\nuser = User(**payload.model_dump(include={"email", "name"}))',
      prompt: "The request body is splatted into a model. Define an input schema with only client-writable fields and construct the model from those fields explicitly; set role/owner server-side.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html", CWE(915), OWASP_TOP10],
    });
  }
  for (const m of rawMatches(fc, /\bfields\s*=\s*["']__all__["']/g)) {
    const cls = [...fc.code.slice(0, m.index).matchAll(/^class[ \t]+(\w+)[ \t]*\(([^)]*)\)/gm)];
    const serializer = [...cls].reverse().find((c) => /Serializer/.test(c[2] as string));
    if (!serializer) continue;
    const name = serializer[1] as string;
    if (/(?:Read|List|Public|Out|Response|Display)/.test(name) || /\bread_only_fields\b/.test(fc.code)) continue;
    fc.report({
      ruleId: "PY-013", offset: m.index, confidence: "medium",
      title: `Serializer ${name} exposes every model field (fields = '__all__')`,
      explanation:
        `${name} serializes every field of the model, including ones added later. When it is used to create or update ` +
        "records, clients can write privileged fields (is_staff, owner, price) and read private ones.",
      fixSummary: "List the fields explicitly and mark server-controlled ones read-only.",
      fixCode: 'class Meta:\n    model = Order\n    fields = ("id", "items", "note")\n    read_only_fields = ("id",)',
      prompt: `Replace fields = '__all__' in ${name} with an explicit tuple of safe fields and set read_only_fields for server-controlled ones.`,
      references: ["https://www.django-rest-framework.org/api-guide/serializers/#specifying-which-fields-to-include", CWE(915), OWASP_TOP10],
    });
  }
}

const JWT_CALL = /\bjwt\s*\.\s*(?:encode|decode)\s*\(/;

/** PY-014: JWT signature verification disabled, `none` algorithm, or literal signing secrets. */
export function jwtMisuse(fc: FileCheck): void {
  if (!/\bjwt\b/.test(fc.pt.raw)) return;
  for (const call of callsMatching(fc, JWT_CALL)) {
    const raw = rawArgText(fc, call);
    const isDecode = /decode\s*\($/.test(fc.code.slice(call.index, call.open + 1));
    const offVerify =
      isDecode && (/["']verify_signature["']\s*:\s*False/.test(raw) || /\bverify\s*=\s*False\b/.test(raw));
    const noneAlg = /algorithms?\s*=\s*[[(]?[^\])]*["'](?:none|None|NONE)["']/.test(raw);
    if (offVerify || noneAlg) {
      fc.report({
        ruleId: "PY-014", offset: call.index, severity: "critical",
        title: offVerify ? "JWT signature verification is disabled" : "JWT accepts the 'none' algorithm",
        explanation:
          "The token is accepted without checking its signature. Anyone can craft a token claiming to be any user or admin " +
          "(just base64 JSON) and the server will trust it: full authentication bypass.",
        fixSummary: "Always verify the signature with a fixed algorithm list and a secret from the environment.",
        fixCode: 'claims = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])',
        prompt: "jwt.decode is called without signature verification (or allows alg none). Verify with a fixed algorithms=['HS256'] and the secret from os.environ; reject tokens that fail.",
        references: ["https://pyjwt.readthedocs.io/en/stable/usage.html", CWE(347), OWASP_TOP10],
      });
      continue;
    }
    const keyArg = call.args[1];
    const keyStart = keyArg ? trimStart(fc.code, keyArg.start, keyArg.end) : -1;
    const lit = keyArg ? fc.pt.stringAt(keyStart) : undefined;
    const kw = /\b(?:key|secret)\s*=\s*(?=[rbuRBU]{0,2}["'])/.exec(argText(fc, call));
    const kwLit = kw ? fc.pt.stringAt(call.open + 1 + kw.index + kw[0].length) : undefined;
    const secret = lit && lit.start === keyStart && !lit.hasInterp ? lit : kwLit;
    if (!secret || secret.hasInterp || secret.value === "") continue;
    fc.report({
      ruleId: "PY-014", offset: call.index, severity: "high", secret: secret.value,
      title: "JWT signed with a hardcoded secret",
      explanation:
        "The JWT signing secret is a literal in source code. Anyone who can read the repository can mint valid tokens for " +
        "any user, including admins. Rotate the secret: the committed value is burned.",
      fixSummary: "Load the signing key from the environment and rotate it.",
      fixCode: 'JWT_SECRET = os.environ["JWT_SECRET"]\ntoken = jwt.encode(payload, JWT_SECRET, algorithm="HS256")',
      prompt: "The JWT secret is hardcoded. Read it from os.environ['JWT_SECRET'] (no default) and rotate the leaked value.",
      references: ["https://pyjwt.readthedocs.io/en/stable/usage.html", CWE(798), OWASP_TOP10],
    });
  }
}

const FAST_HASH = /\bhashlib\s*\.\s*(?:md5|sha1|sha224|sha256|sha384|sha512)\s*\(/;
const PASSWORD_NAME = /\b\w*(?:password|passwd|pwd)\w*\b/i;
const PASSWORD_KEY = /\[\s*["']\w*(?:password|passwd|pwd)\w*["']\s*\]|\.get\s*\(\s*["']\w*(?:password|passwd|pwd)/i;

/** PY-015: fast general-purpose hashes used for passwords. */
export function weakPasswordHash(fc: FileCheck): void {
  for (const call of callsMatching(fc, FAST_HASH)) {
    // Identifier names (code view) or a password-ish dict key / .get() key (the key itself is a string literal).
    if (!PASSWORD_NAME.test(argText(fc, call)) && !PASSWORD_KEY.test(rawArgText(fc, call))) continue;
    const algo = /hashlib\s*\.\s*(\w+)/.exec(fc.code.slice(call.index, call.open))?.[1] ?? "md5";
    fc.report({
      ruleId: "PY-015", offset: call.index, title: `Password hashed with ${algo}`,
      explanation:
        `Passwords are hashed with ${algo}, which is designed to be fast. If your user table ever leaks, attackers test ` +
        "billions of guesses per second on a GPU and recover most real passwords within hours, then reuse them on other sites.",
      fixSummary: "Use a purpose-built slow password hash (argon2, bcrypt, scrypt) with a per-user salt.",
      fixCode:
        'from argon2 import PasswordHasher\n\nph = PasswordHasher()\nhashed = ph.hash(password)\nph.verify(hashed, password)\n# Flask: werkzeug.security.generate_password_hash; Django: make_password',
      prompt: `Passwords are hashed with hashlib.${algo}. Replace with argon2-cffi (or bcrypt / the framework's make_password) and re-hash existing users on next login.`,
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html", CWE(916), OWASP_TOP10],
    });
  }
}
