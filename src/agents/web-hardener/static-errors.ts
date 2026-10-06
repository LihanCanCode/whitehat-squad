import { guardMatches, handlerUnits, matchClose, parseParams } from "../../core/source/index.js";
import type { FunctionUnit } from "../../core/source/index.js";
import type { Finding } from "../../core/types.js";
import { make } from "./fixes.js";
import { bareMatches, lineAt, snippetOf } from "./util.js";
import type { WebFile } from "./util.js";

const RESPONSE_SINK = new RegExp(
  String.raw`\b(?:Next)?Response\s*\.\s*json\s*\(|\bnew\s+(?:Next)?Response\s*\(|\b(?:res|reply|ctx|c|response)\s*(?:\.\s*status\s*\([^)]*\)\s*)?\.\s*(?:json|send|end|text)\s*\(`,
  "g",
);
const CATCH = /\bcatch\s*(?:\(\s*([A-Za-z_$][\w$]*)[^)]*\))?\s*\{/g;
const DEV_GUARD = /NODE_ENV|\bisDev\w*|\bIS_DEV\w*|__DEV__|\bisProduction\b/;
const SAFE_BRANCH = /instanceof\s+(?!Error\b)[\w.]+|\.name\s*===?\s*["'][\w]*Error["']|\bisAxiosError\b|\bisHttpError\b/;

type Leak = "stack" | "message" | undefined;

function leakOf(args: string, v: string): Leak {
  const id = v.replace(/\$/g, String.raw`\$`);
  if (new RegExp(String.raw`(?<![\w$.])${id}\s*\??\.\s*stack\b`).test(args)) return "stack";
  const forms = [
    String.raw`(?<![\w$.])${id}\s*\??\.\s*(?:message|cause|toString\s*\(\s*\))`,
    String.raw`\bString\s*\(\s*${id}\s*\)`,
    String.raw`\$\{\s*${id}\s*\}`,
    String.raw`\bJSON\s*\.\s*stringify\s*\(\s*${id}\s*[,)]`,
    String.raw`[\w$]\s*:\s*${id}\s*(?:[,}]|$)`,
    String.raw`^\s*${id}\s*(?:,|$)`,
  ];
  return forms.some((f) => new RegExp(f).test(args)) ? "message" : undefined;
}

interface Region {
  readonly unit: FunctionUnit;
  readonly start: number;
  readonly end: number;
  readonly v: string;
}

function regions(file: WebFile): Region[] {
  const { src } = file;
  const units = handlerUnits(src).filter((u) => !u.action && u.role !== "middleware");
  const out: Region[] = [];
  for (const u of units) {
    const ps = parseParams(u.params);
    if (ps.length >= 4 && /^_?err/i.test(ps[0]?.names[0] ?? "")) out.push({ unit: u, start: u.bodyStart, end: u.end, v: ps[0]?.names[0] ?? "err" });
  }
  for (const m of bareMatches(src, CATCH)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    const unit = units.filter((u) => open >= u.start && open < u.end).sort((a, b) => a.end - a.start - (b.end - b.start))[0];
    if (close > 0 && unit && m[1]) out.push({ unit, start: open, end: close, v: m[1] });
  }
  return out;
}

/** True when the sink sits behind a dev-only switch or inside a branch for a known, safe error class. */
function guarded(file: WebFile, r: Region, sinkAt: number): boolean {
  // Webhook signature failures ('Webhook Error: ...') only describe the signature check, never app internals.
  if (guardMatches(file.src, r.unit, "signature").some((g) => g.index < r.start)) return true;
  const before = file.src.code.slice(r.start, sinkAt);
  if (DEV_GUARD.test(before)) return true;
  const lastIf = before.lastIndexOf("if (");
  return lastIf >= 0 && SAFE_BRANCH.test(before.slice(lastIf, lastIf + 160)) && before.indexOf("}", lastIf) < 0;
}

export function errorLeakFindings(file: WebFile, target: string): Finding[] {
  if (/\.config\.[cm]?[jt]s$/.test(file.path)) return []; // dev-server plugins in vite/webpack configs are not production handlers
  const out: Finding[] = [];
  const seen = new Set<number>();
  const { src } = file;
  for (const r of regions(file)) {
    for (const m of bareMatches(src, RESPONSE_SINK)) {
      if (m.index < r.start || m.index >= r.end || seen.has(m.index)) continue;
      const open = m.index + m[0].length - 1;
      const close = m[0].endsWith("(") ? matchClose(src, open) : -1;
      if (close < 0) continue;
      const leak = leakOf(src.bare.slice(open + 1, close - 1), r.v);
      if (!leak || guarded(file, r, m.index)) continue;
      seen.add(m.index);
      const line = lineAt(file, m.index);
      const stack = leak === "stack";
      out.push(
        make({
          ruleId: "WEB-011",
          title: stack ? "Error stack trace returned to clients" : "Error details returned to clients",
          severity: stack ? "high" : "medium",
          confidence: "high",
          explanation:
            `This handler sends the caught error (${stack ? "its stack trace" : `${r.v}.message or the whole error`}) back in the HTTP response. ` +
            "Error text from databases, SDKs and your own code includes table and column names, file paths, internal hostnames and sometimes secrets, which hands an attacker a map of your system and confirms injection attempts.",
          evidence: [{ file: file.path, line, snippet: snippetOf(file, m.index) }],
          fix: {
            summary: "Log the error server-side and return a generic message; expose only messages from your own safe error classes.",
            config: "} catch (err) {\n  console.error('chat route failed', err);\n  return Response.json({ error: 'Something went wrong' }, { status: 500 });\n}",
            agentPrompt: `In ${file.path} at line ${line}, stop returning the caught error to the client. Log it on the server and respond with a generic message and status code; keep specific messages only for instanceof ZodError or your own AppError with safe text.`,
            references: ["https://owasp.org/www-community/Improper_Error_Handling", "https://cwe.mitre.org/data/definitions/209.html"],
          },
          target,
          cwe: "CWE-209",
        }),
      );
    }
  }
  return out;
}
