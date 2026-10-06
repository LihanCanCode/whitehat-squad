/**
 * Developer harness: run one agent (or the whole squad) over local checkouts and print a compact
 * finding list for false-positive triage. Never part of the published package.
 *
 *   npx tsx scripts/corpus.ts <agent-id|all> <dir> [<dir> ...]
 */
import path from "node:path";
import { indexDirectory } from "../src/core/fs-walk.js";
import { runScan } from "../src/core/orchestrator.js";
import { SQUAD } from "../src/core/registry.js";

const [agentId, ...dirs] = process.argv.slice(2);
if (!agentId || dirs.length === 0) {
  process.stderr.write("usage: npx tsx scripts/corpus.ts <agent-id|all> <dir> [<dir> ...]\n");
  process.exit(2);
}
const agents = agentId === "all" ? SQUAD : SQUAD.filter((a) => a.id === agentId || a.id === "recon");
if (agents.length === 0) {
  process.stderr.write(`unknown agent "${agentId}"; known: ${SQUAD.map((a) => a.id).join(", ")}\n`);
  process.exit(2);
}

for (const dir of dirs) {
  const root = path.resolve(dir);
  const report = await runScan({ mode: "static", targetLabel: path.basename(root), root, files: await indexDirectory(root), agents });
  const errors = report.agents.filter((a) => a.error).map((a) => `${a.id}: ${a.error}`);
  process.stdout.write(`\n=== ${path.basename(root)} — ${report.findings.length} finding(s)${errors.length ? ` — ERRORS: ${errors.join("; ")}` : ""}\n`);
  for (const f of report.findings) {
    const e = f.evidence[0];
    const where = e?.file ? `${e.file}:${e.line ?? ""}` : (e?.url ?? "");
    process.stdout.write(`  ${f.severity.padEnd(8)} ${f.confidence.padEnd(6)} ${f.ruleId.padEnd(9)} ${where} | ${f.title.slice(0, 90)}\n`);
  }
}
