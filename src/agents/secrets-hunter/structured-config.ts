import { readValue, type Assignment } from "./config-values.js";

/** Config formats whose literal values are not covered by SEC-090 (it only reads unquoted values in .env files). */
export type StructuredKind = "compose" | "workflow" | "dockerfile" | "properties";

const COMPOSE = /(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/i;
const WORKFLOW = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const DOCKERFILE = /(?:^|\/)Dockerfile(?:\.[\w.-]+)?$|\.dockerfile$/i;
const PROPERTIES = /\.properties$/i;

const BLOCK_START: Readonly<Record<"compose" | "workflow", RegExp>> = {
  compose: /^(\s*)(?:environment|args):\s*(?:#.*)?$/,
  workflow: /^(\s*)env:\s*(?:#.*)?$/,
};
const LIST_ITEM = /^\s*-\s*["']?([A-Za-z_]\w*)=(.*?)["']?\s*$/;
const MAP_ITEM = /^\s*([A-Za-z_][\w.-]*)\s*:\s*(.*)$/;
const DOCKER_PAIR = /([A-Za-z_]\w*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)/g;
const DOCKER_INSTRUCTION = /^\s*(ENV|ARG)\s+(.+)$/i;
const DOCKER_SPACE_FORM = /^([A-Za-z_]\w*)\s+(.+)$/;
const PROPERTY = /^\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*)$/;

export function structuredKind(relPath: string): StructuredKind | null {
  if (/\.dockerignore$/i.test(relPath)) return null;
  if (WORKFLOW.test(relPath)) return "workflow";
  if (COMPOSE.test(relPath)) return "compose";
  if (DOCKERFILE.test(relPath)) return "dockerfile";
  if (PROPERTIES.test(relPath)) return "properties";
  return null;
}

const indentOf = (line: string): number => line.length - line.trimStart().length;

/** `environment:` / `args:` (compose) or `env:` (workflow) blocks, in map form and `- KEY=value` list form. */
function yamlBlockAssignments(lines: readonly string[], kind: "compose" | "workflow"): Assignment[] {
  const out: Assignment[] = [];
  let blockIndent = -1;
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    const indent = indentOf(line);
    if (blockIndent >= 0 && indent <= blockIndent && !(indent === blockIndent && trimmed.startsWith("- "))) blockIndent = -1;
    if (blockIndent < 0) {
      if (BLOCK_START[kind].test(line)) blockIndent = indent;
      return;
    }
    const list = LIST_ITEM.exec(line);
    const map = list ? null : MAP_ITEM.exec(line);
    const name = list?.[1] ?? map?.[1];
    const raw = list?.[2] ?? map?.[2];
    if (!name || raw === undefined || /^[|>][+-]?$/.test(raw.trim())) return;
    const value = readValue(raw);
    if (value !== null) out.push({ name, value, line: i + 1 });
  });
  return out;
}

function dockerAssignments(lines: readonly string[]): Assignment[] {
  const out: Assignment[] = [];
  lines.forEach((line, i) => {
    const m = DOCKER_INSTRUCTION.exec(line);
    if (!m) return;
    const instruction = (m[1] ?? "").toUpperCase();
    const rest = m[2] ?? "";
    const pairs = [...rest.matchAll(DOCKER_PAIR)];
    if (pairs.length > 0) {
      for (const p of pairs) {
        const value = readValue(p[2] ?? "");
        if (value !== null) out.push({ name: p[1] ?? "", value, line: i + 1 });
      }
    } else if (instruction === "ENV") {
      const space = DOCKER_SPACE_FORM.exec(rest);
      const value = space ? readValue(space[2] ?? "") : null;
      if (space && value !== null) out.push({ name: space[1] ?? "", value, line: i + 1 });
    }
  });
  return out;
}

function propertyAssignments(lines: readonly string[]): Assignment[] {
  const out: Assignment[] = [];
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed.startsWith("!")) return;
    const m = PROPERTY.exec(line);
    if (m) out.push({ name: m[1] ?? "", value: (m[2] ?? "").trim(), line: i + 1 });
  });
  return out;
}

export function structuredAssignments(text: string, kind: StructuredKind): Assignment[] {
  const lines = text.split(/\r?\n/);
  if (kind === "dockerfile") return dockerAssignments(lines);
  if (kind === "properties") return propertyAssignments(lines);
  return yamlBlockAssignments(lines, kind);
}
