import { describe, expect, it } from "vitest";
import { agent } from "../../../src/agents/database-guard/index.js";
import { memContext } from "../../helpers/memfs.js";

const scan = (files: Record<string, string>) => agent.run(memContext(files));

describe("Firebase rules", () => {
  it("flags open firestore rules as critical DB-010", async () => {
    const f = await scan({
      "firestore.rules": "service cloud.firestore { match /databases/{d}/documents { match /{doc=**} { allow read, write: if true; } } }",
    });
    expect(f.map((x) => x.ruleId)).toEqual(["DB-010"]);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.cwe).toBe("CWE-284");
    expect(f[0]!.fix.config).toContain("request.auth");
  });

  it("flags test-mode expiry and names the date", async () => {
    const f = await scan({
      "firestore.rules": "match /{d=**} {\n allow read, write: if request.time < timestamp.date(2030, 1, 15);\n}",
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.explanation).toContain("2030-01-15");
    expect(f[0]!.evidence[0]!.line).toBe(2);
  });

  it("treats read-only open rules as high", async () => {
    const f = await scan({ "firestore.rules": "match /x/{id} { allow get, list: if true; }" });
    expect(f[0]!.severity).toBe("high");
  });

  it("flags open storage rules as DB-011", async () => {
    const f = await scan({ "storage.rules": "match /b/{b}/o { match /{all=**} { allow read, write: if true; } }" });
    expect(f.map((x) => x.ruleId)).toEqual(["DB-011"]);
  });

  it("flags realtime database rules", async () => {
    const f = await scan({
      "database.rules.json": '{ "rules": { ".read": true, ".write": "true", "x": { ".write": "now < 1999999999999" } } }',
    });
    expect(f.map((x) => x.ruleId)).toEqual(["DB-010", "DB-010", "DB-010"]);
    expect(f.every((x) => x.severity === "critical" || x.severity === "high")).toBe(true);
  });

  it("is quiet for authenticated rules and commented-out rules", async () => {
    const f = await scan({
      "firestore.rules": "// allow read, write: if true;\nmatch /u/{id} { allow read, write: if request.auth != null && request.auth.uid == id; }",
      "database.rules.json": '{ "rules": { ".read": false, ".write": false, "users": { "$uid": { ".read": "auth != null && auth.uid === $uid" } } } }',
      "apps/web/storage.rules": "/* allow write: if true; */",
    });
    expect(f).toEqual([]);
  });

  it("finds rules files in subdirectories", async () => {
    const f = await scan({ "backend/firestore.rules": "allow write: if true;" });
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence[0]!.file).toBe("backend/firestore.rules");
  });
});
