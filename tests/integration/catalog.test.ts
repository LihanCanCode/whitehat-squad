import { promises as fs } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SEVERITIES } from "../../src/core/severity.js";
import { ALL_RULES, ruleMeta } from "../../src/rules/catalog.js";

const ROOT = path.resolve(import.meta.dirname, "../..");
// Real ids only (DB-012, WEB-L07). Prose like "DB-API" and URL fragments like "CICD-SEC-03-…" are not ids.
const RULE_ID = /(?<![A-Za-z0-9-])(?:SEC|DB|AUTH|WEB|SUP|AI|INJ|PY|REV|RECON|CFG)-L?\d{2,3}(?![A-Za-z0-9-])/g;
/** Documentation placeholders that look like ids but are not rules. */
const PLACEHOLDERS = new Set(["AI-00X", "SEC-XXX", "DB-XXX"]);

async function listTs(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await listTs(full)));
    else if (e.isFile() && e.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

/** rule id -> agent folders whose source mentions it (rules.meta.ts excluded: it is the catalog). */
async function idsInSource(): Promise<Map<string, Set<string>>> {
  const found = new Map<string, Set<string>>();
  const files = [...(await listTs(path.join(ROOT, "src/agents"))), ...(await listTs(path.join(ROOT, "src/data")))];
  for (const file of files) {
    if (file.endsWith("rules.meta.ts")) continue;
    const rel = path.relative(path.join(ROOT, "src"), file).split(path.sep);
    const owner = rel[0] === "agents" ? (rel[1] as string) : `data/${rel[1] ?? ""}`;
    const text = await fs.readFile(file, "utf8");
    for (const id of text.match(RULE_ID) ?? []) {
      if (PLACEHOLDERS.has(id)) continue;
      const set = found.get(id) ?? new Set<string>();
      set.add(owner);
      found.set(id, set);
    }
  }
  return found;
}

function groupByAgent(ids: readonly string[], owners: ReadonlyMap<string, ReadonlySet<string>>): string {
  const groups = new Map<string, string[]>();
  for (const id of ids) {
    for (const owner of owners.get(id) ?? new Set(["(unknown)"])) {
      groups.set(owner, [...(groups.get(owner) ?? []), id]);
    }
  }
  return [...groups.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([agent, list]) => `  ${agent}: ${[...new Set(list)].sort().join(", ")}`)
    .join("\n");
}

describe("rule catalog", () => {
  it("has unique ids, non-empty text and a valid severity for every rule", () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(ids.filter((id, i) => ids.indexOf(id) !== i), "duplicate ids").toEqual([]);
    for (const r of ALL_RULES) {
      expect(r.id, r.id).toMatch(/^[A-Z]+-[A-Z0-9]+$/);
      expect(r.title.trim(), `${r.id} title`).not.toBe("");
      expect(r.summary.trim(), `${r.id} summary`).not.toBe("");
      expect(r.fix.trim(), `${r.id} fix`).not.toBe("");
      expect(SEVERITIES, `${r.id} severity`).toContain(r.severity);
      expect(r.modes.length, `${r.id} modes`).toBeGreaterThan(0);
      if (r.cwe) expect(r.cwe, `${r.id} cwe`).toMatch(/^CWE-\d+$/);
    }
  });

  it("looks rules up by id", () => {
    expect(ruleMeta("AUTH-002")?.agent).toBe("auth-auditor");
    expect(ruleMeta("NOPE-999")).toBeUndefined();
  });

  it("knows every rule id that appears in agent and data source", async () => {
    const owners = await idsInSource();
    const known = new Set(ALL_RULES.map((r) => r.id));
    const missing = [...owners.keys()].filter((id) => !known.has(id)).sort();
    expect(missing, `rule ids used in src but missing from the catalog, by agent:\n${groupByAgent(missing, owners)}\n`).toEqual([]);
  });

  it("does not list a rule that no source raises", async () => {
    const owners = await idsInSource();
    // AI review classes are raised by the model through the hunter schema enum (checked below).
    const stale = ALL_RULES.filter((r) => r.agent !== "ai-review").map((r) => r.id).filter((id) => !owners.has(id)).sort();
    const byAgent = new Map(ALL_RULES.map((r) => [r.id, new Set([r.agent])]));
    expect(stale, `catalog ids never mentioned in src, by agent:\n${groupByAgent(stale, byAgent)}\n`).toEqual([]);
  });

  it("the AI review hunter schema accepts exactly the ai-review catalog classes", async () => {
    const { HUNTER_SCHEMA } = await import("../../src/review/prompts.js");
    const items = (HUNTER_SCHEMA.properties.candidates as { items: { properties: { class: { enum: string[] } } } }).items;
    expect([...items.properties.class.enum].sort()).toEqual(ALL_RULES.filter((r) => r.agent === "ai-review").map((r) => r.id).sort());
  });

  it.each(["auth-auditor", "ai-guard", "web-hardener", "recon"])("%s catalog matches its source exactly", async (agent) => {
    const owners = await idsInSource();
    const inSource = [...owners.entries()].filter(([, o]) => o.has(agent)).map(([id]) => id).sort();
    const inCatalog = ALL_RULES.filter((r) => r.agent === agent).map((r) => r.id).sort();
    expect(inCatalog).toEqual(inSource);
  });
});
