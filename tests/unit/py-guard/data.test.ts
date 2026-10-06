import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/py-guard/index.js";
import { memContext } from "../../helpers/memfs.js";
import { only, scanOne } from "./helpers.js";

const FLASK = "from flask import Flask, request, send_file, send_from_directory\nimport pickle\nimport yaml\nimport requests\nimport os\napp = Flask(__name__)\n";
const route = (body: string): string => `${FLASK}\n@app.route("/x", methods=["POST"])\ndef x():\n${body}`;

describe("PY-008 unsafe deserialization", () => {
  it("flags pickle.loads on request data, uploads and via a variable", async () => {
    expect(only(await scanOne(route("    return pickle.loads(request.data)\n")), "PY-008")).toHaveLength(1);
    expect(only(await scanOne(route('    return pickle.load(request.files["m"])\n')), "PY-008")).toHaveLength(1);
    const via = route('    blob = request.get_data()\n    obj = dill.loads(blob)\n    return "ok"\n').replace("import pickle", "import pickle, dill");
    const f = only(await scanOne(via), "PY-008");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-502" });
  });
  it("flags marshal.loads on a FastAPI body param", async () => {
    const code = "from fastapi import FastAPI, Request\nimport marshal\napp = FastAPI()\n@app.post('/m')\nasync def m(payload: bytes):\n    return marshal.loads(payload)\n";
    expect(only(await scanOne(code), "PY-008")).toHaveLength(1);
  });
  it("does NOT flag pickle on trusted local files", async () => {
    const code = `${FLASK}def load():\n    with open("model.pkl", "rb") as fh:\n        return pickle.load(fh)\n`;
    expect(only(await scanOne(code), "PY-008")).toEqual([]);
  });
  it("flags yaml.load without SafeLoader and passes safe variants", async () => {
    const bad = only(await scanOne(`${FLASK}def f(s):\n    return yaml.load(s)\n`), "PY-008");
    expect(bad).toHaveLength(1);
    expect(bad[0]?.title).toMatch(/yaml/);
    expect(only(await scanOne(`${FLASK}def f(s):\n    return yaml.load(s, Loader=yaml.FullLoader)\n`), "PY-008")).toHaveLength(1);
    const ok =
      `${FLASK}def f(s):\n    a = yaml.safe_load(s)\n    b = yaml.load(s, Loader=yaml.SafeLoader)\n    c = yaml.load(s, yaml.SafeLoader)\n    d = yaml.load(s, Loader=yaml.CSafeLoader)\n    return a, b, c, d\n`;
    expect(only(await scanOne(ok), "PY-008")).toEqual([]);
  });
});

describe("PY-010 SSRF", () => {
  it("flags requests.get on a query parameter and a variable derived from it", async () => {
    expect(only(await scanOne(route('    return requests.get(request.args["url"]).text\n')), "PY-010")).toHaveLength(1);
    const f = only(await scanOne(route('    target = request.json["url"]\n    return requests.post(target, json={}).text\n')), "PY-010");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-918" });
  });
  it("flags httpx and urlopen on FastAPI parameters", async () => {
    const code = "from fastapi import FastAPI\nimport httpx\nfrom urllib.request import urlopen\napp = FastAPI()\n@app.get('/p')\nasync def p(url: str):\n    r = httpx.get(url)\n    return urlopen(url).read()\n";
    expect(only(await scanOne(code), "PY-010")).toHaveLength(2);
  });
  it("flags requests.request(method, url) using the second argument", async () => {
    expect(only(await scanOne(route('    return requests.request("GET", request.args["u"]).text\n')), "PY-010")).toHaveLength(1);
  });
  it("does NOT flag fixed hosts, constant URLs, or a hostname allowlist in the same function", async () => {
    const fixed = route('    uid = request.args["id"]\n    return requests.get(f"https://api.example.com/users/{uid}").text\n');
    expect(only(await scanOne(fixed), "PY-010")).toEqual([]);
    expect(only(await scanOne(route('    return requests.get("https://example.com").text\n')), "PY-010")).toEqual([]);
    const guarded = route(
      '    url = request.args["url"]\n    host = urlparse(url).hostname\n    if host not in ALLOWED_HOSTS:\n        abort(400)\n    return requests.get(url, timeout=5).text\n',
    );
    expect(only(await scanOne(guarded), "PY-010")).toEqual([]);
  });
});

describe("PY-011 path traversal", () => {
  it("flags open() / send_file() on request-derived paths", async () => {
    const a = route('    name = request.args["f"]\n    return open(os.path.join("uploads", name)).read()\n');
    const f = only(await scanOne(a), "PY-011");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-22" });
    expect(only(await scanOne(route('    return send_file(request.args["f"])\n')), "PY-011")).toHaveLength(1);
  });
  it("flags FileResponse on a FastAPI path param", async () => {
    const code = "from fastapi import FastAPI\nfrom fastapi.responses import FileResponse\napp = FastAPI()\n@app.get('/d/{path}')\nasync def d(path: str):\n    return FileResponse(f'static/{path}')\n";
    expect(only(await scanOne(code), "PY-011")).toHaveLength(1);
  });
  it("flags send_from_directory only when the directory is user controlled", async () => {
    expect(only(await scanOne(route('    return send_from_directory(request.args["d"], "a.txt")\n')), "PY-011")).toHaveLength(1);
    expect(only(await scanOne(route('    return send_from_directory("uploads", request.args["f"])\n')), "PY-011")).toEqual([]);
  });
  it("does NOT flag sanitized or contained paths", async () => {
    const sanitized = `${FLASK}from werkzeug.utils import secure_filename\n\n@app.route("/u")\ndef u():\n    name = secure_filename(request.args["f"])\n    return open(os.path.join("uploads", name)).read()\n`;
    expect(only(await scanOne(sanitized), "PY-011")).toEqual([]);
    const inline = route('    return open(os.path.basename(request.args["f"])).read()\n');
    expect(only(await scanOne(inline), "PY-011")).toEqual([]);
    const contained = route(
      '    p = os.path.realpath(os.path.join("uploads", request.args["f"]))\n    if not p.startswith("/srv/uploads"):\n        abort(400)\n    return open(p).read()\n',
    );
    expect(only(await scanOne(contained), "PY-011")).toEqual([]);
    expect(only(await scanOne(route('    return open("static/readme.txt").read()\n')), "PY-011")).toEqual([]);
  });
});

describe("PY-013 mass assignment", () => {
  it("flags Model(**request.json) and .create(**request.get_json())", async () => {
    const code = `${FLASK}\n@app.route("/u", methods=["POST"])\ndef mk():\n    u = User(**request.json)\n    User.objects.create(**request.get_json())\n    return "ok"\n`;
    const f = only(await scanOne(code), "PY-013");
    expect(f).toHaveLength(2);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.cwe).toBe("CWE-915");
  });
  it("flags **payload.model_dump() into an ORM model from a FastAPI body, with medium confidence", async () => {
    const code = "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/u')\ndef mk(payload: UserIn, db):\n    u = User(**payload.model_dump())\n    return u\n";
    const f = only(await scanOne(code), "PY-013");
    expect(f).toHaveLength(1);
    expect(f[0]?.confidence).toBe("medium");
  });
  it("flags DRF fields = '__all__' on a writable serializer", async () => {
    const code = "from rest_framework import serializers\n\nclass OrderSerializer(serializers.ModelSerializer):\n    class Meta:\n        model = Order\n        fields = '__all__'\n";
    expect(only(await scanOne(code, "serializers.py"), "PY-013")).toHaveLength(1);
  });
  it("does NOT flag explicit fields, read serializers, non-model splats or plain dict splats", async () => {
    const drf = "class OrderSerializer(serializers.ModelSerializer):\n    class Meta:\n        model = Order\n        fields = ('id', 'note')\n";
    expect(only(await scanOne(drf, "serializers.py"), "PY-013")).toEqual([]);
    const read = "class OrderReadSerializer(serializers.ModelSerializer):\n    class Meta:\n        fields = '__all__'\n";
    expect(only(await scanOne(read, "serializers.py"), "PY-013")).toEqual([]);
    const other = `${FLASK}\n@app.route("/p")\ndef p():\n    return render(**request.args)\n`;
    expect(only(await scanOne(other), "PY-013")).toEqual([]);
    const notBody = "from fastapi import FastAPI\napp = FastAPI()\ndef build(cfg):\n    return User(**cfg.dict())\n";
    expect(only(await scanOne(notBody), "PY-013")).toEqual([]);
    const notSerializer = "class Thing:\n    fields = '__all__'\n";
    expect(only(await scanOne(notSerializer), "PY-013")).toEqual([]);
  });
});

describe("PY-014 JWT misuse", () => {
  const JWT = "import jwt\nimport os\n";
  it("flags disabled signature verification and alg none as critical", async () => {
    const a = only(await scanOne(`${JWT}def f(t):\n    return jwt.decode(t, options={"verify_signature": False})\n`), "PY-014");
    expect(a).toHaveLength(1);
    expect(a[0]).toMatchObject({ severity: "critical", cwe: "CWE-347" });
    const b = only(await scanOne(`${JWT}def f(t):\n    return jwt.decode(t, key, algorithms=["none"])\n`), "PY-014");
    expect(b[0]?.severity).toBe("critical");
    expect(only(await scanOne(`${JWT}def f(t):\n    return jwt.decode(t, verify=False)\n`), "PY-014")).toHaveLength(1);
  });
  it("flags hardcoded secrets in encode/decode and redacts them", async () => {
    const secret = "my-super-secret-signing-key-2024";
    const code = `${JWT}def f(t, p):\n    a = jwt.encode(p, "${secret}", algorithm="HS256")\n    return jwt.decode(t, key="${secret}", algorithms=["HS256"])\n`;
    const ctx = memContext({ "app.py": code });
    const f = only(await agent.run(ctx), "PY-014");
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.severity === "high")).toBe(true);
    expect(JSON.stringify(f)).not.toContain(secret);
    expect(ctx.secrets.has(secret)).toBe(true);
  });
  it("does NOT flag verified tokens with env secrets", async () => {
    const code = `${JWT}def f(t, p):\n    a = jwt.encode(p, os.environ["JWT_SECRET"], algorithm="HS256")\n    b = jwt.decode(t, os.environ["JWT_SECRET"], algorithms=["HS256"])\n    c = jwt.decode(t, options={"verify_exp": True}, key=KEY, algorithms=["RS256"])\n    d = jwt.encode(p, f"{prefix}x", algorithm="HS256")\n    e = jwt.encode(p, "", algorithm="HS256")\n    return a, b, c, d, e\n`;
    expect(only(await scanOne(code), "PY-014")).toEqual([]);
  });
  it("ignores files that do not use jwt", async () => {
    expect(only(await scanOne("def f(x):\n    return other.decode(x, verify=False)\n"), "PY-014")).toEqual([]);
  });
});

describe("PY-015 weak password hashing", () => {
  it.each(["md5", "sha1", "sha256"])("flags hashlib.%s over a password", async (algo) => {
    const code = `import hashlib\n\ndef hash_pw(password):\n    return hashlib.${algo}(password.encode()).hexdigest()\n`;
    const f = only(await scanOne(code), "PY-015");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-916" });
    expect(f[0]?.title).toContain(algo);
  });
  it("flags salted-but-fast hashing and user_password names", async () => {
    const code = "import hashlib\n\ndef h(user_password, salt):\n    return hashlib.sha256((salt + user_password).encode()).hexdigest()\n";
    expect(only(await scanOne(code), "PY-015")).toHaveLength(1);
  });
  it("does NOT flag hashes of non-passwords or password KDFs", async () => {
    const code =
      "import hashlib\n\ndef f(data, password, salt):\n" +
      "    a = hashlib.sha256(data).hexdigest()\n" +
      "    b = hashlib.md5(etag_source).hexdigest()\n" +
      "    c = hashlib.pbkdf2_hmac('sha256', password, salt, 600000)\n" +
      "    d = hashlib.sha256(b'password').hexdigest()\n" +
      "    return a, b, c, d\n";
    expect(only(await scanOne(code), "PY-015")).toEqual([]);
  });
});
