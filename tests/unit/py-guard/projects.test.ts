import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/py-guard/index.js";
import { frameworksInManifests, frameworksInSource } from "../../../src/agents/py-guard/frameworks.js";
import { RULES } from "../../../src/agents/py-guard/rules.meta.js";
import { memContext } from "../../helpers/memfs.js";
import { idsOf, only, scan } from "./helpers.js";

const FLASK_PROJECT: Record<string, string> = {
  "requirements.txt": "Flask==3.0.0\nflask-cors==4.0.0\nrequests\n",
  "app.py": `import os, subprocess, pickle, hashlib
import requests
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "dev-secret-key-please-change"
CORS(app, supports_credentials=True)


@app.route("/search")
def search():
    term = request.args.get("q")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return jsonify(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text


@app.route("/download")
def download():
    return send_file(request.args["name"])


@app.route("/restore", methods=["POST"])
def restore():
    return str(pickle.loads(request.data))


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    pw = hashlib.md5(data["password"].encode()).hexdigest()
    user = User(**request.json)
    db.session.add(user)
    db.session.commit()
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
`,
};

const DJANGO_PROJECT: Record<string, string> = {
  "requirements.txt": "Django>=4.2\ndjangorestframework\n",
  "mysite/settings.py": `import os
SECRET_KEY = 'django-insecure-k3y!abcdef123456'
DEBUG = True
ALLOWED_HOSTS = ['*']
INSTALLED_APPS = ['django.contrib.admin', 'rest_framework', 'shop']
SESSION_COOKIE_SECURE = False
`,
  "shop/views.py": `from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import yaml


@csrf_exempt
def update_profile(request):
    if request.method == "POST":
        Profile.objects.filter(user=request.user).update(bio=request.POST["bio"])
    return JsonResponse({"ok": True})


def report(request):
    name = request.GET.get("name")
    return User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")


def import_config(request):
    return yaml.load(request.body)
`,
  "shop/serializers.py": `from rest_framework import serializers


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'
`,
};

const FASTAPI_PROJECT: Record<string, string> = {
  "pyproject.toml": '[project]\ndependencies = ["fastapi>=0.110", "uvicorn"]\n',
  "main.py": `import jwt
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


@app.get("/users/{user_id}")
def get_user(user_id: str, db=Depends(get_db)):
    return db.execute(text(f"SELECT * FROM users WHERE id = '{user_id}'")).first()


@app.post("/token-check")
def check(token: str):
    return jwt.decode(token, options={"verify_signature": False})


@app.post("/calc")
async def calc(expr: str):
    return {"result": eval(expr)}
`,
};

describe("realistic Flask project", () => {
  it("finds the classic AI-generated mistakes with accurate severities and line evidence", async () => {
    const fs = await scan(FLASK_PROJECT);
    const bySev = (id: string) => only(fs, id).map((f) => f.severity);
    expect(bySev("PY-001")).toEqual(["high"]);
    expect(bySev("PY-003")).toEqual(["high"]);
    expect(bySev("PY-005")).toEqual(["high"]);
    expect(bySev("PY-006")).toEqual(["critical"]);
    expect(bySev("PY-007")).toEqual(["critical"]);
    expect(bySev("PY-008")).toEqual(["high"]);
    expect(bySev("PY-010")).toEqual(["high"]);
    expect(bySev("PY-011")).toEqual(["high"]);
    expect(bySev("PY-013")).toEqual(["medium"]);
    expect(bySev("PY-015")).toEqual(["high"]);
    expect(only(fs, "PY-012").map((f) => f.evidence[0]?.line)).toEqual([11]);
    for (const f of fs) {
      expect(f.agentId).toBe("py-guard");
      expect(f.evidence[0]?.file).toBe("app.py");
      expect(f.evidence[0]?.line).toBeGreaterThan(0);
      expect(f.evidence[0]?.snippet.length).toBeLessThanOrEqual(200);
      expect(f.fix.agentPrompt).toMatch(/app\.py at line \d+/);
      expect(f.fix.config?.length).toBeGreaterThan(10);
      expect(f.fix.references.length).toBeGreaterThan(0);
      expect(f.explanation.length).toBeGreaterThan(80);
      expect(f.cwe).toMatch(/^CWE-\d+$/);
      expect(f.verify.ruleId).toBe(f.ruleId);
    }
    expect(JSON.stringify(fs)).not.toContain("dev-secret-key-please-change");
  });
});

describe("realistic Django project", () => {
  it("flags settings, csrf_exempt, raw SQL, yaml.load and serializer fields", async () => {
    const fs = await scan(DJANGO_PROJECT);
    expect(idsOf(fs)).toEqual(["PY-002", "PY-003", "PY-004", "PY-006", "PY-008", "PY-013"]);
    expect(only(fs, "PY-002").map((f) => f.severity).sort()).toEqual(["high", "medium"]);
    expect(only(fs, "PY-004")).toHaveLength(2);
    expect(only(fs, "PY-006")[0]?.severity).toBe("critical");
    expect(only(fs, "PY-003")[0]?.evidence[0]?.file).toBe("mysite/settings.py");
  });
});

describe("realistic FastAPI project", () => {
  it("flags CORS, SQL via path param, jwt verification off and eval", async () => {
    const fs = await scan(FASTAPI_PROJECT);
    expect(only(fs, "PY-005")).toHaveLength(1);
    expect(only(fs, "PY-006")[0]?.severity).toBe("critical");
    expect(only(fs, "PY-014")[0]?.severity).toBe("critical");
    expect(only(fs, "PY-009")[0]?.severity).toBe("critical");
    expect(only(fs, "PY-012").length).toBeGreaterThanOrEqual(1);
  });
});

describe("clean, well-built FastAPI app", () => {
  const CLEAN: Record<string, string> = {
    "requirements.txt": "fastapi\nuvicorn\nsqlalchemy\nargon2-cffi\nPyJWT\nPyYAML\n",
    "app/config.py": `import os
from functools import lru_cache


@lru_cache
def settings():
    return {
        "secret": os.environ["JWT_SECRET"],
        "origins": os.environ.get("ALLOWED_ORIGINS", "https://app.example.com").split(","),
        "debug": os.environ.get("DEBUG") == "1",
    }
`,
    "app/auth.py": `import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        claims = jwt.decode(token, settings()["secret"], algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)
    return claims["sub"]
`,
    "app/main.py": `import subprocess
import yaml
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text
from app.auth import get_current_user
from app.config import settings

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings()["origins"],
    allow_credentials=True,
)
ph = PasswordHasher()


class NoteIn(BaseModel):
    title: str


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register")
def register(email: str, password: str, db=Depends(get_db)):
    db.execute(text("INSERT INTO users (email, pw) VALUES (:e, :p)"), {"e": email, "p": ph.hash(password)})
    db.commit()


@app.get("/notes/{note_id}")
def read_note(note_id: int, db=Depends(get_db), user=Depends(get_current_user)):
    # SELECT * FROM notes WHERE id = {note_id}  -- never format SQL: use bound params
    row = db.execute(text("SELECT * FROM notes WHERE id = :id AND owner = :o"), {"id": note_id, "o": user}).first()
    if row is None:
        raise HTTPException(status_code=404)
    return row


@app.post("/notes")
def create_note(note: NoteIn, db=Depends(get_db), current_user=Depends(get_current_user)):
    db.execute("INSERT INTO notes (title, owner) VALUES (%s, %s)", (note.title, current_user))
    db.commit()


@app.get("/convert")
def convert(name: str, user=Depends(get_current_user)):
    if name not in {"a", "b"}:
        raise HTTPException(status_code=400)
    subprocess.run(["convert", f"{name}.png", "out.jpg"], check=True)
    return yaml.safe_load("ok: true")
`,
  };

  it("produces ZERO findings", async () => {
    expect(await scan(CLEAN)).toEqual([]);
  });

  it("still fires when one safe pattern is regressed (control)", async () => {
    const regressed = {
      ...CLEAN,
      "app/main.py": (CLEAN["app/main.py"] as string).replace(
        'db.execute(text("SELECT * FROM notes WHERE id = :id AND owner = :o"), {"id": note_id, "o": user}).first()',
        "db.execute(text(f\"SELECT * FROM notes WHERE id = {note_id}\")).first()",
      ),
    };
    const fs = await scan(regressed);
    expect(only(fs, "PY-006")).toHaveLength(1);
    expect(fs).toHaveLength(1);
  });
});

describe("agent behavior", () => {
  it("has the required identity", () => {
    expect(agent).toMatchObject({ id: "py-guard", name: "PyGuard", modes: ["static"] });
    expect(agent.role).toMatch(/Python/);
  });
  it("returns nothing for projects without Python files", async () => {
    expect(await scan({ "index.js": "eval(req.query.x)", "README.md": "app.run(debug=True)" })).toEqual([]);
  });
  // .gitignore cannot hide committed code (security review): secret_local.py is still analysed.
  it("skips venv, site-packages and tests, but not git-ignored Python files", async () => {
    const bad = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n";
    const fs = await scan({
      "venv/lib/x.py": bad,
      "lib/site-packages/y.py": bad,
      "tests/test_app.py": bad,
      "test_app.py": bad,
      "conftest.py": bad,
      "secret_local.py": bad,
      ".gitignore": "secret_local.py\n",
    });
    expect([...new Set(fs.map((f) => f.evidence[0]?.file))]).toEqual(["secret_local.py"]);
  });
  it("skips unreadable files", async () => {
    const ctx = memContext({});
    const files = { ...ctx.files, paths: ["ghost.py"], read: async () => null };
    expect(await agent.run({ ...ctx, files })).toEqual([]);
  });
  it("uses ctx.root as the verify target when present", async () => {
    const ctx = memContext({ "app.py": "from flask import Flask\napp = Flask(__name__)\napp.debug = True\n" });
    const fs = await agent.run({ ...ctx, root: "D:/proj" });
    expect(fs[0]?.verify.target).toBe("D:/proj");
  });
  it("is stable: finding ids are deterministic and unique per distinct snippet", async () => {
    const a = await scan(FLASK_PROJECT);
    const b = await scan(FLASK_PROJECT);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(new Set(a.map((f) => f.id)).size).toBe(a.length);
  });
  it("completes quickly on a large file (10k lines)", async () => {
    const big = "from flask import Flask\napp = Flask(__name__)\n" + "x = compute(1, 2)\n".repeat(10_000);
    const start = Date.now();
    expect(await scan({ "big.py": big })).toEqual([]);
    expect(Date.now() - start).toBeLessThan(3000);
  });
  it("handles Unicode, emoji and CRLF sources", async () => {
    const src = "from flask import Flask\r\napp = Flask(__name__)\r\n# 日本語 🔥\r\nname = 'héllo 🎉'\r\napp.run(debug=True)\r\n";
    const fs = await scan({ "app.py": src });
    expect(fs).toHaveLength(1);
    expect(fs[0]?.evidence[0]?.line).toBe(5);
    expect(fs[0]?.evidence[0]?.snippet).toBe("app.run(debug=True)");
  });
});

describe("framework detection", () => {
  it("reads imports", () => {
    expect([...frameworksInSource("from flask import Flask\nimport django\nfrom starlette.routing import Route")].sort()).toEqual(["django", "fastapi", "flask"]);
    expect(frameworksInSource("import requests").size).toBe(0);
  });
  it("reads requirements, pyproject, Pipfile and setup.py but not look-alike packages", async () => {
    const ctx = memContext({
      "requirements.txt": "flask-cors==4.0\nrequests\n",
      "api/requirements-dev.txt": "Django==4.2\n",
      "pyproject.toml": 'dependencies = ["fastapi>=0.1"]\n',
      "node_modules/x/requirements.txt": "flask\n",
    });
    expect([...(await frameworksInManifests(ctx))].sort()).toEqual(["django", "fastapi"]);
    const pip = memContext({ Pipfile: '[packages]\nflask = "*"\n', "setup.py": "install_requires=['starlette']\n" });
    expect([...(await frameworksInManifests(pip))].sort()).toEqual(["fastapi", "flask"]);
  });
  it("uses manifest frameworks for Django settings that do not import django", async () => {
    const fs = await scan({ "requirements.txt": "django\n", "conf/settings.py": "DEBUG = True\n" });
    expect(only(fs, "PY-002")).toHaveLength(1);
  });
});

describe("rule catalog", () => {
  it("has unique PY ids with complete metadata", () => {
    const ids = RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of RULES) {
      expect(r.id).toMatch(/^PY-0\d\d$/);
      expect(r.agent).toBe("py-guard");
      expect(r.cwe).toMatch(/^CWE-\d+$/);
      expect(r.owasp).toMatch(/^A\d\d$/);
      expect(r.modes).toEqual(["static"]);
      expect(r.summary.length).toBeGreaterThan(60);
      expect(r.fix.length).toBeGreaterThan(20);
    }
  });
  it("every rule is raisable: every finding's ruleId exists in the catalog and its cwe matches", async () => {
    const all = [
      ...(await scan(FLASK_PROJECT)),
      ...(await scan(DJANGO_PROJECT)),
      ...(await scan(FASTAPI_PROJECT)),
    ];
    const seen = new Set(all.map((f) => f.ruleId));
    for (const f of all) {
      const meta = RULES.find((r) => r.id === f.ruleId);
      expect(meta).toBeDefined();
      expect(f.cwe).toBe(meta?.cwe);
    }
    const missing = RULES.map((r) => r.id).filter((id) => !seen.has(id));
    expect(missing).toEqual([]);
  });
});
