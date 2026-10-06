import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/py-guard/index.js";
import { memContext } from "../../helpers/memfs.js";
import { only, scan, scanOne } from "./helpers.js";

const FLASK = "from flask import Flask\napp = Flask(__name__)\n";

describe("PY-001 Flask debug", () => {
  it("flags app.run(debug=True) in a Flask app", async () => {
    const f = only(await scanOne(`${FLASK}\nif __name__ == "__main__":\n    app.run(host="0.0.0.0", debug=True)\n`), "PY-001");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-489", agentId: "py-guard" });
    expect(f[0]?.evidence[0]?.line).toBe(5);
    expect(f[0]?.fix.agentPrompt).toContain("app.py at line 5");
    expect(f[0]?.fix.config).toContain("os.environ");
  });
  it("flags app.debug = True and FLASK_DEBUG set in code", async () => {
    const f = only(await scanOne(`import os\n${FLASK}app.debug = True\nos.environ["FLASK_DEBUG"] = "1"\nos.environ.setdefault("FLASK_DEBUG", "true")\n`), "PY-001");
    expect(f).toHaveLength(3);
  });
  it("does not flag env-driven debug", async () => {
    expect(only(await scanOne(`import os\n${FLASK}app.run(debug=os.environ.get("FLASK_DEBUG") == "1")\n`), "PY-001")).toEqual([]);
  });
  it("does not flag FLASK_DEBUG=0 or a run() outside Flask files", async () => {
    expect(only(await scanOne(`import os\n${FLASK}os.environ["FLASK_DEBUG"] = "0"\nserver.run(debug=True)\n`), "PY-001")).toHaveLength(1);
    expect(only(await scanOne(`import os\nos.environ["FLASK_DEBUG"] = "0"\nserver.run(debug=True)\n`), "PY-001")).toEqual([]);
  });
  it("skips examples/ and tests/ paths and commented-out code", async () => {
    const code = `${FLASK}app.run(debug=True)\n`;
    expect(await scanOne(code, "examples/demo/app.py")).toEqual([]);
    expect(await scanOne(code, "tests/app.py")).toEqual([]);
    expect(only(await scanOne(`${FLASK}# app.run(debug=True)\ns = "app.run(debug=True)"\n`), "PY-001")).toEqual([]);
  });
  it("honors whsquad-ignore", async () => {
    expect(only(await scanOne(`${FLASK}app.run(debug=True)  # whsquad-ignore PY-001\n`), "PY-001")).toEqual([]);
  });
  it("flags FLASK_DEBUG=1 in a committed .flaskenv but not when git-ignored or off", async () => {
    expect(only(await scan({ ".flaskenv": "FLASK_APP=app\nFLASK_DEBUG=1\n" }), "PY-001")).toHaveLength(1);
    expect(only(await scan({ ".flaskenv": "FLASK_ENV=development\n" }), "PY-001")).toHaveLength(1);
    expect(only(await scan({ ".env": "FLASK_DEBUG=1\n", ".gitignore": ".env\n" }), "PY-001")).toEqual([]);
    expect(only(await scan({ ".flaskenv": "FLASK_DEBUG=0\n" }), "PY-001")).toEqual([]);
  });
});

describe("PY-002 Django settings", () => {
  it("flags DEBUG = True in settings.py and ALLOWED_HOSTS wildcard", async () => {
    const fs = await scanOne("DEBUG = True\nALLOWED_HOSTS = ['*']\nINSTALLED_APPS = []\n", "config/settings.py");
    const f = only(fs, "PY-002");
    expect(f.map((x) => x.severity).sort()).toEqual(["high", "medium"]);
    expect(f.find((x) => x.severity === "medium")?.title).toMatch(/ALLOWED_HOSTS/);
  });
  it("does not flag env-driven DEBUG, real hosts, conditional or dev settings", async () => {
    const ok = 'import os\nDEBUG = os.environ.get("DEBUG") == "1"\nALLOWED_HOSTS = ["example.com"]\n';
    expect(await scanOne(ok, "config/settings.py")).toEqual([]);
    expect(await scanOne("if ENV == 'dev':\n    DEBUG = True\n", "config/settings.py")).toEqual([]);
    expect(await scanOne("DEBUG = True\nALLOWED_HOSTS = ['*']\n", "config/settings/local.py")).toEqual([]);
    expect(await scanOne("DEBUG = True\n", "utils/helpers.py")).toEqual([]);
  });
  it("detects settings via INSTALLED_APPS in any file and supports tuples", async () => {
    const fs = await scanOne("INSTALLED_APPS = ['a']\nALLOWED_HOSTS = ('*',)\n", "core/conf.py");
    expect(only(fs, "PY-002")).toHaveLength(1);
  });
  it("does not flag ALLOWED_HOSTS with unbalanced brackets", async () => {
    expect(only(await scanOne("INSTALLED_APPS = []\nALLOWED_HOSTS = [\n", "settings.py"), "PY-002")).toEqual([]);
  });
});

describe("PY-003 hardcoded secret key", () => {
  it("flags Flask secret_key and config['SECRET_KEY'], redacting and registering the value", async () => {
    const secret = "xK9mPq2vL8nR4tYw7ZaB3cD5eF6gH1";
    const code = `${FLASK}app.secret_key = "${secret}"\napp.config["SECRET_KEY"] = 'another-literal-secret-value-123'\n`;
    const ctx = memContext({ "app.py": code });
    const fs = only(await agent.run(ctx), "PY-003");
    expect(fs).toHaveLength(2);
    expect(JSON.stringify(fs)).not.toContain(secret);
    expect(ctx.secrets.has(secret)).toBe(true);
  });
  it("flags django-insecure placeholder in settings", async () => {
    const fs = only(await scanOne("SECRET_KEY = 'django-insecure-abc123'\nINSTALLED_APPS = []\n", "proj/settings.py"), "PY-003");
    expect(fs).toHaveLength(1);
    expect(fs[0]?.explanation).toMatch(/django-insecure/);
    expect(fs[0]?.severity).toBe("high");
  });
  it("does not flag env-driven keys, empty literals or interpolations", async () => {
    const ok = `import os\n${FLASK}app.secret_key = os.environ["SECRET_KEY"]\napp.config["SECRET_KEY"] = os.getenv("SECRET_KEY")\n`;
    expect(only(await scanOne(ok), "PY-003")).toEqual([]);
    expect(only(await scanOne(`${FLASK}app.secret_key = ""\nSECRET_KEY = f"{base}-x"\n`), "PY-003")).toEqual([]);
    expect(only(await scanOne(`${FLASK}# app.secret_key = "abcdef"\n`), "PY-003")).toEqual([]);
    expect(only(await scanOne(`${FLASK}app.config["SECRET_KEY"] = ""\n`), "PY-003")).toEqual([]);
  });
});

describe("PY-004 CSRF and cookies", () => {
  it("flags @csrf_exempt on a view that writes data", async () => {
    const code =
      "from django.views.decorators.csrf import csrf_exempt\n\n@csrf_exempt\ndef transfer(request):\n" +
      "    if request.method == 'POST':\n        Account.objects.filter(id=1).update(balance=0)\n    return ok()\n";
    const f = only(await scanOne(code, "views.py"), "PY-004");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.title).toContain("transfer");
  });
  it("does not flag read-only exempt views or signature-verified webhooks", async () => {
    const ro = "@csrf_exempt\ndef ping(request):\n    return JsonResponse({'ok': True})\n";
    expect(only(await scanOne(ro, "views.py"), "PY-004")).toEqual([]);
    const hook = "@csrf_exempt\ndef stripe_hook(request):\n    event = stripe.Webhook.construct_event(request.body, sig, secret)\n    Order.objects.create(x=1)\n";
    expect(only(await scanOne(hook, "views.py"), "PY-004")).toEqual([]);
    const named = "@csrf_exempt\ndef github_webhook(request):\n    Order.objects.create(x=1)\n";
    expect(only(await scanOne(named, "views.py"), "PY-004")).toEqual([]);
  });
  it("flags WTF_CSRF_ENABLED = False and the config item form", async () => {
    const f = only(await scanOne(`${FLASK}app.config["WTF_CSRF_ENABLED"] = False\nclass Config:\n    WTF_CSRF_ENABLED = False\n`), "PY-004");
    expect(f).toHaveLength(2);
  });
  it("flags insecure cookie flags in non-dev settings only", async () => {
    const code = "INSTALLED_APPS = []\nSESSION_COOKIE_SECURE = False\nCSRF_COOKIE_SECURE = False\n";
    expect(only(await scanOne(code, "proj/settings.py"), "PY-004")).toHaveLength(2);
    expect(only(await scanOne(code, "proj/settings/dev.py"), "PY-004")).toEqual([]);
    expect(only(await scanOne("class TestingConfig:\n    SESSION_COOKIE_SECURE = False\n    WTF_CSRF_ENABLED = False\n"), "PY-004")).toEqual([]);
    expect(only(await scanOne("SESSION_COOKIE_SECURE = True\n", "proj/settings.py"), "PY-004")).toEqual([]);
  });
});

describe("PY-005 CORS", () => {
  const FASTAPI = "from fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\n";
  it("flags wildcard origins with credentials", async () => {
    const f = only(await scanOne(`${FASTAPI}app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["*"],\n    allow_credentials=True,\n)\n`), "PY-005");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.cwe).toBe("CWE-942");
  });
  it("flags allow_origin_regex '.*' with credentials", async () => {
    expect(only(await scanOne(`${FASTAPI}app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)\n`), "PY-005")).toHaveLength(1);
  });
  it("does not flag explicit origins, wildcard without credentials, or a non-wildcard regex", async () => {
    expect(only(await scanOne(`${FASTAPI}app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)\n`), "PY-005")).toEqual([]);
    expect(only(await scanOne(`${FASTAPI}app.add_middleware(CORSMiddleware, allow_origins=["*"])\n`), "PY-005")).toEqual([]);
    expect(only(await scanOne(`${FASTAPI}app.add_middleware(CORSMiddleware, allow_origin_regex="https://.*[.]example[.]com", allow_credentials=True)\n`), "PY-005")).toEqual([]);
    expect(only(await scanOne(`${FASTAPI}app.add_middleware(CORSMiddleware, allow_credentials=True)\n`), "PY-005")).toEqual([]);
  });
  it("flags Flask-CORS with credentials and default or wildcard origins", async () => {
    const imp = "from flask import Flask\nfrom flask_cors import CORS\napp = Flask(__name__)\n";
    expect(only(await scanOne(`${imp}CORS(app, supports_credentials=True)\n`), "PY-005")).toHaveLength(1);
    expect(only(await scanOne(`${imp}CORS(app, supports_credentials=True, origins="*")\n`), "PY-005")).toHaveLength(1);
    expect(only(await scanOne(`${imp}CORS(app, supports_credentials=True, origins=["https://a.com"])\n`), "PY-005")).toEqual([]);
    expect(only(await scanOne(`${imp}CORS(app)\n`), "PY-005")).toEqual([]);
  });
  it("ignores CORS() when flask_cors is not imported", async () => {
    expect(only(await scanOne("CORS(app, supports_credentials=True)\n"), "PY-005")).toEqual([]);
  });
});
