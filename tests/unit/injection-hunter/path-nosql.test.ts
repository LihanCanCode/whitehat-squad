import { describe, expect, it } from "vitest";
import { express, only, route, scan, scanOne } from "./helpers.js";

const FS = `const fs = require("fs");\nconst path = require("path");`;

describe("INJ-007 path traversal", () => {
  it("flags readFile of a joined tainted path (high, CWE-22)", async () => {
    const code = express("  const file = path.join(__dirname, \"uploads\", req.params.name);\n  const data = await fs.promises.readFile(file);\n  res.send(data);", FS);
    const f = only(await scanOne(code), "INJ-007");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-22" });
    expect(f[0]?.fix.agentPrompt).toContain("server.js");
    expect(f[0]?.fix.patch?.diff).toContain("basename");
  });
  it("flags readFileSync, createReadStream, sendFile, download, readdir, stat", async () => {
    for (const body of [
      "  fs.readFileSync(path.join(DIR, req.query.f));",
      "  fs.createReadStream(DIR + req.query.f).pipe(res);",
      "  res.sendFile(path.join(DIR, req.params.name));",
      "  res.download(DIR + \"/\" + req.query.f);",
      "  fs.readdirSync(path.join(DIR, req.query.d));",
      "  await fs.promises.stat(path.resolve(DIR, req.query.f));",
    ]) {
      expect(only(await scanOne(express(body, FS + "\nconst DIR = '/srv';")), "INJ-007"), body).toHaveLength(1);
    }
  });
  it("flags unlink / rm as critical", async () => {
    for (const body of ["  fs.unlinkSync(path.join(DIR, req.body.f));", "  await fs.promises.rm(DIR + req.body.f, { recursive: true });", "  fs.unlink(path.join(DIR, req.body.f), () => {});"]) {
      const f = only(await scanOne(express(body, FS + "\nconst DIR = '/srv';")), "INJ-007");
      expect(f, body).toHaveLength(1);
      expect(f[0]?.severity, body).toBe("critical");
    }
  });
  it("flags bare imported readFile from fs/promises, but only when fs is imported", async () => {
    const code = express("  const t = await readFile(path.join(DIR, req.query.f), \"utf8\");", `import { readFile } from "fs/promises";\nimport path from "path";\nconst DIR = "/srv";`);
    expect(only(await scanOne(code), "INJ-007")).toHaveLength(1);
    const nofs = express("  const t = await readFile(req.query.f);");
    expect(only(await scanOne(nofs), "INJ-007")).toEqual([]);
  });
  it("does not flag basename, resolve+startsWith, includes('..') guards or sendFile with root; flags the bare control", async () => {
    const base = express("  const f = path.basename(req.params.name);\n  fs.readFileSync(path.join(DIR, f));", FS + "\nconst DIR = '/srv';");
    expect(only(await scanOne(base), "INJ-007")).toEqual([]);
    const resolved = express(
      "  const full = path.resolve(DIR, req.params.name);\n  if (!full.startsWith(path.resolve(DIR) + path.sep)) return res.sendStatus(400);\n  fs.readFileSync(full);",
      FS + "\nconst DIR = '/srv';",
    );
    expect(only(await scanOne(resolved), "INJ-007")).toEqual([]);
    const dots = express('  const n = req.params.name;\n  if (n.includes("..")) return res.sendStatus(400);\n  fs.readFileSync(path.join(DIR, n));', FS + "\nconst DIR = '/srv';");
    expect(only(await scanOne(dots), "INJ-007")).toEqual([]);
    const root = express("  res.sendFile(req.params.name, { root: DIR });", FS + "\nconst DIR = '/srv';");
    expect(only(await scanOne(root), "INJ-007")).toEqual([]);
    const control = express("  fs.readFileSync(path.join(DIR, req.params.name));", FS + "\nconst DIR = '/srv';");
    expect(only(await scanOne(control), "INJ-007")).toHaveLength(1);
  });
  it("does not flag constant paths or non-fs readFile receivers", async () => {
    const code = express("  fs.readFileSync(path.join(process.cwd(), \"public\", \"a.txt\"));\n  await store.readFile(req.query.f);\n  await Bun.file(req.query.f);", FS);
    expect(only(await scanOne(code), "INJ-007")).toEqual([]);
  });
  it("works in Next route handlers with dynamic params", async () => {
    const code = `import fs from "node:fs";\nimport path from "node:path";\nexport async function GET(req: Request, { params }: { params: { name: string } }) {\n  const buf = fs.readFileSync(path.join(process.cwd(), "files", params.name));\n  return new Response(buf);\n}\n`;
    expect(only(await scanOne(code, "app/files/[name]/route.ts"), "INJ-007")).toHaveLength(1);
  });
});

describe("INJ-008 NoSQL operator injection", () => {
  const M = `const mongoose = require("mongoose");\nconst User = mongoose.model("User", new mongoose.Schema({}));`;
  it("flags a filter value taken directly from the body (high, CWE-943)", async () => {
    const code = express("  const user = await User.findOne({ email: req.body.email, password: req.body.password });\n  res.json(user);", M);
    const f = only(await scanOne(code), "INJ-008");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cwe: "CWE-943" });
    expect(f[0]?.fix.patch?.diff).toContain("String(");
  });
  it("flags destructured values, shorthand, whole-object filters and other query methods", async () => {
    for (const body of [
      "  const { email } = req.body;\n  await User.findOne({ email });",
      "  const { email } = req.body;\n  await User.findOne({ email: email });",
      "  await User.find(req.query);",
      "  await User.deleteOne({ _id: req.params.id, owner: req.body.owner });",
      "  await User.updateOne({ token: req.body.token }, { $set: { used: true } });",
      "  await User.countDocuments({ name: req.query.name });",
      "  await db.collection(\"users\").findOne({ email: req.body.email });",
    ]) {
      expect(only(await scanOne(express(body, M)), "INJ-008"), body).toHaveLength(1);
    }
  });
  it("does not flag String(), templates, $eq, schema parse, typeof guards; flags the raw control", async () => {
    const safe = express(
      '  await User.findOne({ email: String(req.body.email) });\n  await User.findOne({ email: `${req.body.email}` });\n  await User.findOne({ email: { $eq: req.body.email } });\n  const { name } = schema.parse(req.body);\n  await User.findOne({ name });',
      M,
    );
    expect(only(await scanOne(safe), "INJ-008")).toEqual([]);
    const typed = express('  const { email } = req.body;\n  if (typeof email !== "string") return res.sendStatus(400);\n  await User.findOne({ email });', M);
    expect(only(await scanOne(typed), "INJ-008")).toEqual([]);
    const control = express("  const { email } = req.body;\n  await User.findOne({ email });", M);
    expect(only(await scanOne(control), "INJ-008")).toHaveLength(1);
  });
  it("does not flag when mongo-sanitize / sanitizeFilter is used anywhere in the project", async () => {
    const files = {
      "server.js": express("  await User.findOne({ email: req.body.email });", M),
      "app.js": 'const mongoSanitize = require("express-mongo-sanitize");\napp.use(mongoSanitize());\n',
    };
    expect(only(await scan(files), "INJ-008")).toEqual([]);
    expect(only(await scan({ "server.js": files["server.js"] }), "INJ-008")).toHaveLength(1);
  });
  it("does not flag Array.find, non-mongo files, or untainted filters", async () => {
    const arr = express("  const u = users.find((x) => x.email === req.body.email);\n  const v = users.find(req.body.pred);", M);
    expect(only(await scanOne(arr), "INJ-008")).toEqual([]);
    const nomongo = express("  await User.findOne({ email: req.body.email });");
    expect(only(await scanOne(nomongo), "INJ-008")).toEqual([]);
    const clean = express('  await User.findOne({ email: "a@b.c" });', M);
    expect(only(await scanOne(clean), "INJ-008")).toEqual([]);
  });
  it("works in a Next route handler with mongodb", async () => {
    const code = route("  const body = await req.json();\n  const u = await users.findOne({ email: body.email });\n  return Response.json(u);", `import { MongoClient } from "mongodb";`);
    expect(only(await scanOne(code, "app/api/login/route.ts"), "INJ-008")).toHaveLength(1);
  });
});
