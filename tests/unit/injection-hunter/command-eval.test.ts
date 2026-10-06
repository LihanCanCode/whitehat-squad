import { describe, expect, it } from "vitest";
import { express, only, route, scanOne } from "./helpers.js";

const CP = `const { exec, execSync, spawn, execFile } = require("child_process");`;

describe("INJ-004 command injection", () => {
  it("flags exec with a tainted template (critical, CWE-78)", async () => {
    const code = express("  const { host } = req.body;\n  exec(`ping -c 1 ${host}`, (e, out) => res.send(out));", CP);
    const f = only(await scanOne(code), "INJ-004");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-78" });
    expect(f[0]?.fix.patch?.diff).toContain("execFile");
    expect(f[0]?.fix.agentPrompt).toContain("server.js");
    expect(f[0]?.fix.references.some((r) => r.includes("OS_Command_Injection"))).toBe(true);
  });
  it("flags execSync concatenation, child_process.exec, a lone tainted command and promisified exec", async () => {
    for (const body of [
      '  execSync("convert " + req.query.file + " out.png");',
      "  require(\"child_process\").exec(`ls ${req.query.dir}`);",
      "  exec(req.body.cmd);",
      "  await execAsync(`git clone ${req.body.repo}`);",
    ]) {
      expect(only(await scanOne(express(body, CP + "\nconst execAsync = require('util').promisify(exec);")), "INJ-004"), body).toHaveLength(1);
    }
  });
  it("flags spawn / execa with shell:true and sh -c", async () => {
    for (const body of [
      "  spawn(`tar -xf ${req.body.f}`, { shell: true });",
      '  spawn("grep", [req.body.q, "file"], { shell: true });',
      '  spawn("sh", ["-c", `echo ${req.body.m}`]);',
      "  await execa(`ls ${req.query.d}`, { shell: true });",
    ]) {
      expect(only(await scanOne(express(body, CP + "\nconst { execa } = require('execa');")), "INJ-004"), body).toHaveLength(1);
    }
  });
  it("does not flag execFile / spawn with an args array and no shell; still flags exec", async () => {
    const safe = express('  execFile("ping", ["-c", "1", req.body.host]);\n  spawn("convert", [req.query.file, "out.png"]);\n  spawn("sh", ["-c", "echo hi"]);', CP);
    expect(only(await scanOne(safe), "INJ-004")).toEqual([]);
    const control = express("  exec(`ping ${req.body.host}`);", CP);
    expect(only(await scanOne(control), "INJ-004")).toHaveLength(1);
  });
  it("does not flag regex .exec, constant commands or sanitized numbers; still flags raw value", async () => {
    const safe = express('  const m = /a(.)/.exec(req.body.s);\n  exec("git status");\n  exec(`head -n ${Number(req.query.n)} log.txt`);\n  const home = "x";\n  exec(`ls ${home}`);', CP);
    expect(only(await scanOne(safe), "INJ-004")).toEqual([]);
    const raw = express("  exec(`head -n ${req.query.n} log.txt`);", CP);
    expect(only(await scanOne(raw), "INJ-004")).toHaveLength(1);
  });
  it("does not flag an allowlisted value; flags the same code without the check", async () => {
    const guarded = express('  const { tool } = req.body;\n  if (!TOOLS.includes(tool)) return res.sendStatus(400);\n  exec(`${tool} --version`);', CP + '\nconst TOOLS = ["git", "node"];');
    expect(only(await scanOne(guarded), "INJ-004")).toEqual([]);
    const open = express("  const { tool } = req.body;\n  exec(`${tool} --version`);", CP);
    expect(only(await scanOne(open), "INJ-004")).toHaveLength(1);
  });
  it("needs a child_process import for bare exec names", async () => {
    const code = express("  exec(`ping ${req.body.host}`);");
    expect(only(await scanOne(code), "INJ-004")).toEqual([]);
  });
  it("works in a Next route handler", async () => {
    const code = route("  const { url } = await req.json();\n  execSync(`curl ${url}`);", `import { execSync } from "node:child_process";`);
    expect(only(await scanOne(code, "app/api/c/route.ts"), "INJ-004")).toHaveLength(1);
  });
});

describe("INJ-009 / INJ-010 eval and dynamic code", () => {
  it("flags eval / new Function / vm.run* on request data as critical INJ-009", async () => {
    for (const body of [
      "  const r = eval(req.body.expr);",
      "  const f = new Function(\"x\", `return ${req.body.expr}`);",
      "  vm.runInNewContext(req.body.code, {});",
      "  const s = new vm.Script(req.body.code);",
      "  const fn = Function(req.query.body);",
    ]) {
      const f = only(await scanOne(express(body, 'const vm = require("vm");')), "INJ-009");
      expect(f, body).toHaveLength(1);
      expect(f[0]).toMatchObject({ severity: "critical", cwe: "CWE-95" });
    }
  });
  it("flags non-literal untainted eval as medium INJ-010 but not literals or .eval members", async () => {
    const code = "export function run(src: string) {\n  return eval(src);\n}\n";
    const f = only(await scanOne(code, "src/lib/run.ts"), "INJ-010");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", confidence: "medium", cwe: "CWE-95" });
    const safe = 'const g = new Function("return this")();\nconst x = eval("1+1");\nawait redis.eval(script, 0);\nawait page.evaluate(src);\n';
    expect(await scanOne(safe, "src/lib/run.ts")).toEqual([]);
  });
  it("does not flag a sanitized/parsed value; still flags the raw one", async () => {
    expect(only(await scanOne(express("  eval(Number(req.body.n) + 1);")), "INJ-009")).toEqual([]);
    expect(only(await scanOne(express("  eval(req.body.n + 1);")), "INJ-009")).toHaveLength(1);
  });
  it("ignores eval in comments, strings and test files", async () => {
    const code = express('  // eval(req.body.x)\n  const s = "eval(req.body.x)";');
    expect(await scanOne(code)).toEqual([]);
    expect(await scanOne(express("  eval(req.body.x);"), "tests/a.test.js")).toEqual([]);
  });
});
