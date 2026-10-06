import { describe, expect, it } from "vitest";
import { only, scanOne } from "./helpers.js";

const FLASK = "from flask import Flask, request\nimport sqlite3\nimport subprocess\nimport os\napp = Flask(__name__)\n";
const route = (body: string): string => `${FLASK}\n@app.route("/x")\ndef x():\n${body}`;

describe("PY-006 SQL injection", () => {
  it("flags f-string execute fed by request input as critical", async () => {
    const code = route('    uid = request.args.get("id")\n    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n    return "ok"\n');
    const f = only(await scanOne(code), "PY-006");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-89" });
    expect(f[0]?.fix.config).toContain("%s");
    expect(f[0]?.fix.agentPrompt).toContain("app.py at line 10");
  });
  it.each([
    ['cur.execute("SELECT * FROM t WHERE a = \'%s\'" % name)', "percent format"],
    ['cur.execute("SELECT * FROM t WHERE a = \'" + name + "\'")', "concatenation"],
    ['cur.execute("SELECT * FROM t WHERE a = \'{}\'".format(name))', ".format"],
    ['cur.executemany(f"INSERT INTO t VALUES ({name})", rows)', "executemany f-string"],
  ])("flags %s (%s) as high when not request-derived", async (stmt) => {
    const f = only(await scanOne(`${FLASK}\ndef job(name):\n    ${stmt}\n`), "PY-006");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });
  it("flags SQL built into a variable first, and escalates for path params", async () => {
    const code = `${FLASK}\n@app.route("/u/<name>")\ndef u(name):\n    sql = f"SELECT * FROM users WHERE name = '{name}'"\n    cur.execute(sql)\n`;
    const f = only(await scanOne(code), "PY-006");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("critical");
  });
  it("flags SQLAlchemy text(f...) once and session.execute(f...)", async () => {
    const sa = "from sqlalchemy import text\n";
    const a = only(await scanOne(`${sa}def f(session, q):\n    session.execute(text(f"SELECT * FROM t WHERE n = '{q}'"))\n`), "PY-006");
    expect(a).toHaveLength(1);
    const b = only(await scanOne(`${sa}def f(session, q):\n    session.execute(f"SELECT * FROM t WHERE n = '{q}'")\n`), "PY-006");
    expect(b).toHaveLength(1);
  });
  it("flags Django .raw(f...) and .extra(where=[f...])", async () => {
    const dj = "from django.db import models\n";
    const raw = only(await scanOne(`${dj}def f(q):\n    return User.objects.raw(f"SELECT * FROM u WHERE n = '{q}'")\n`, "views.py"), "PY-006");
    expect(raw).toHaveLength(1);
    const extra = only(await scanOne(`${dj}def f(q):\n    return User.objects.extra(where=[f"n = '{q}'"])\n`, "views.py"), "PY-006");
    expect(extra).toHaveLength(1);
  });
  it("does NOT flag parameterized queries", async () => {
    const code =
      `${FLASK}from sqlalchemy import text\n\ndef f(session, cur, uid):\n` +
      '    cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n' +
      '    cur.execute("SELECT * FROM t WHERE id = ?", (uid,))\n' +
      '    session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": uid})\n' +
      '    cur.execute("SELECT 1 " "FROM t")\n' +
      '    cur.execute("SELECT " + "1")\n' +
      '    User.objects.raw("SELECT * FROM u WHERE n = %s", [uid])\n' +
      "    cur.execute(query)\n";
    expect(only(await scanOne(code), "PY-006")).toEqual([]);
  });
  it("does not flag when the request value is sanitized with int()", async () => {
    const code = route('    uid = int(request.args.get("id"))\n    cur.execute("SELECT * FROM t WHERE id = " + str(uid))\n');
    const f = only(await scanOne(code), "PY-006");
    // still dynamic SQL (high), but not escalated to critical because uid was cast
    expect(f.every((x) => x.severity === "high")).toBe(true);
  });
  it("ignores SQL in comments and strings and honors whsquad-ignore", async () => {
    expect(only(await scanOne(`${FLASK}# cur.execute(f"SELECT {x}")\ns = 'cur.execute(f"{x}")'\n`), "PY-006")).toEqual([]);
    expect(only(await scanOne(`${FLASK}def f(x):\n    # whsquad-ignore PY-006\n    cur.execute(f"SELECT {x}")\n`), "PY-006")).toEqual([]);
  });
});

describe("PY-007 command injection", () => {
  it("flags shell=True with an f-string built from request input as critical", async () => {
    const code = route('    host = request.args["host"]\n    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)\n    return out\n');
    const f = only(await scanOne(code), "PY-007");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-78" });
  });
  it.each([
    'subprocess.run("ls " + path, shell=True)',
    'subprocess.Popen("ls {}".format(path), shell=True)',
    'subprocess.call("echo %s" % path, shell=True)',
    'os.system(f"rm -rf {path}")',
    "os.popen(path)",
  ])("flags %s as high", async (stmt) => {
    const f = only(await scanOne(`${FLASK}def job(path):\n    ${stmt}\n`), "PY-007");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });
  it("flags a command variable built with an f-string earlier", async () => {
    const code = `${FLASK}def job(path):\n    cmd = f"tar xf {path}"\n    subprocess.run(cmd, shell=True)\n`;
    expect(only(await scanOne(code), "PY-007")).toHaveLength(1);
  });
  it("does NOT flag list args, literal shell commands or constants", async () => {
    const code =
      `${FLASK}def job(path):\n` +
      '    subprocess.run(["ls", path], check=True)\n' +
      '    subprocess.run("ls -la", shell=True)\n' +
      '    subprocess.run(["ls", path], shell=False)\n' +
      '    os.system("clear")\n' +
      '    subprocess.run(cmd, shell=True)\n';
    expect(only(await scanOne(code), "PY-007")).toEqual([]);
  });
  it("still fires for os.system on a tainted name (control)", async () => {
    const code = route('    target = request.form["t"]\n    os.system(target)\n');
    expect(only(await scanOne(code), "PY-007")[0]?.severity).toBe("critical");
  });
});

describe("PY-009 eval/exec", () => {
  it("flags eval on request data as critical", async () => {
    const code = route('    expr = request.args.get("e")\n    return str(eval(expr))\n');
    const f = only(await scanOne(code), "PY-009");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-95" });
  });
  it("flags exec on any non-literal as medium", async () => {
    const f = only(await scanOne("def run(code):\n    exec(code)\n"), "PY-009");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });
  it("flags eval(request.data) directly", async () => {
    expect(only(await scanOne(route("    return eval(request.data)\n")), "PY-009")[0]?.severity).toBe("critical");
  });
  it("does NOT flag literals, ast.literal_eval, method exec/eval or calls without args", async () => {
    const code =
      "import ast\ndef f(x, session):\n" +
      '    eval("1 + 1")\n' +
      "    ast.literal_eval(x)\n" +
      "    session.exec(select(User))\n" +
      "    model.eval(x)\n" +
      "    exec()\n";
    expect(only(await scanOne(code), "PY-009")).toEqual([]);
  });
});
