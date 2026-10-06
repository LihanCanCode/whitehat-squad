import { makeFinding } from "../../core/finding.js";
import type { Agent, Finding, ScanContext } from "../../core/types.js";
import { AGENT_ID, FileCheck } from "./check.js";
import { frameworksInManifests, frameworksInSource, type PyFramework } from "./frameworks.js";
import { corsChecks, csrfChecks, djangoSettings, flaskDebug, flaskDebugEnvFile, hardcodedSecretKey } from "./rules-config.js";
import { jwtMisuse, massAssignment, pathTraversal, ssrf, unsafeDeserialization, weakPasswordHash } from "./rules-data.js";
import { commandInjection, evalExec, sqlInjection } from "./rules-injection.js";
import { hasProjectAuthDependency, unauthenticatedRoutes } from "./rules-routes.js";
import { isTestPath } from "./util.js";

const SKIP_DIR = /(?:^|\/)(?:venv|\.venv|env|site-packages|node_modules|__pycache__|\.tox|\.git)\//;
const ENV_FILE = /(?:^|\/)(?:\.flaskenv|\.env)$/;

function isScannablePython(p: string): boolean {
  return /\.py$/i.test(p) && !SKIP_DIR.test(p) && !isTestPath(p);
}

function envFileFindings(path: string, text: string, target: string): Finding[] {
  const hit = flaskDebugEnvFile(text);
  if (!hit) return [];
  return [
    makeFinding({
      ruleId: "PY-001", agentId: AGENT_ID, title: "Flask debug mode enabled", severity: "high", cwe: "CWE-489",
      explanation:
        "FLASK_DEBUG=1 (or FLASK_ENV=development) is committed in an env file. If it reaches a deployed server, the Werkzeug " +
        "debugger exposes an interactive Python console to anyone who can trigger an error: remote code execution.",
      evidence: [{ file: path, line: hit.line, snippet: hit.snippet }],
      fix: {
        summary: "Keep debug flags out of committed env files; set them only in your local shell.",
        config: "# .flaskenv (committed) - no debug flags\nFLASK_APP=app:app\n# local shell only: export FLASK_DEBUG=1",
        agentPrompt: `In ${path} at line ${hit.line}: remove the debug flag from this committed env file and make sure production never sets FLASK_DEBUG.`,
        references: ["https://flask.palletsprojects.com/en/stable/debugging/", "https://cwe.mitre.org/data/definitions/489.html"],
      },
      target,
    }),
  ];
}

function runFile(fc: FileCheck, projectHasAppDeps: boolean): Finding[] {
  flaskDebug(fc);
  djangoSettings(fc);
  hardcodedSecretKey(fc);
  csrfChecks(fc);
  corsChecks(fc);
  sqlInjection(fc);
  commandInjection(fc);
  unsafeDeserialization(fc);
  evalExec(fc);
  ssrf(fc);
  pathTraversal(fc);
  unauthenticatedRoutes(fc, projectHasAppDeps);
  massAssignment(fc);
  jwtMisuse(fc);
  weakPasswordHash(fc);
  return fc.findings;
}

export const agent: Agent = {
  id: AGENT_ID,
  name: "PyGuard",
  role: "Audits Python backends (Flask, Django, FastAPI) for the mistakes AI assistants make",
  modes: ["static"],
  async run(ctx) {
    const target = ctx.root ?? ".";
    const findings: Finding[] = [];
    const pyPaths = ctx.files.paths.filter((p) => isScannablePython(p));
    const texts = new Map<string, string>();
    for (const p of pyPaths) {
      const text = await ctx.files.read(p);
      if (text !== null) texts.set(p, text);
    }
    const project = new Set<PyFramework>(await frameworksInManifests(ctx));
    let projectHasAppDeps = false;
    for (const text of texts.values()) {
      for (const fw of frameworksInSource(text)) project.add(fw);
      projectHasAppDeps = projectHasAppDeps || hasProjectAuthDependency(text);
    }
    for (const [path, text] of texts) {
      const fc = new FileCheck(path, text, new Set([...project, ...frameworksInSource(text)]), target);
      findings.push(...runFile(fc, projectHasAppDeps));
      for (const s of fc.secrets) ctx.registerSecret(s);
    }
    for (const p of ctx.files.paths) {
      if (!ENV_FILE.test(p) || ctx.files.isIgnored(p) || SKIP_DIR.test(p)) continue;
      const text = await ctx.files.read(p);
      if (text !== null) findings.push(...envFileFindings(p, text, target));
    }
    return findings;
  },
};
