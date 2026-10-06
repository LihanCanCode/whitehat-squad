import type { Confidence } from "../../core/types.js";

export const DOCKER_CONTEXT_RULE_ID = "SEC-112";

export interface ContextCopy {
  readonly line: number;
  readonly snippet: string;
  /** 0-based index of the build stage (FROM) the copy sits in. */
  readonly stage: number;
}

export interface ContextCopies {
  readonly copies: readonly ContextCopy[];
  readonly stageCount: number;
}

// COPY/ADD whose first source is the whole build context: `.` or `./`. Flags such as
// --chown are skipped; --from copies out of another stage, not the context, so it is excluded below.
const COPY_CONTEXT = /^\s*(?:COPY|ADD)\s+((?:--\S+\s+)*)(?:\.|\.\/)(?:\s+\S.*)$/i;
const FROM = /^\s*FROM\s/i;
const WILDCARD_ENV = new Set([".env*", ".env.*", "*.env*", ".env?*"]);
const EXACT_ENV = ".env";

/** Finds `COPY . .` style instructions and which stage of a multi-stage build they belong to. */
export function findContextCopies(dockerfile: string): ContextCopies {
  const copies: ContextCopy[] = [];
  let stage = -1;
  dockerfile.split(/\r?\n/).forEach((line, i) => {
    if (FROM.test(line)) {
      stage++;
      return;
    }
    const m = COPY_CONTEXT.exec(line);
    if (!m || /--from[=\s]/i.test(m[1] ?? "")) return;
    copies.push({ line: i + 1, snippet: line.trim().slice(0, 120), stage: Math.max(stage, 0) });
  });
  return { copies, stageCount: Math.max(stage + 1, 1) };
}

/** `/.env*`, `**\/.env*` and `.env*` all normalise to the same bare pattern. */
function normalizePattern(line: string): string {
  return line.trim().replace(/^\/+/, "").replace(/^(?:\*\*\/)+/, "");
}

/**
 * Whether a .dockerignore keeps `.env*` files out of the build context. A bare `.env` counts only
 * when it is the only kind of env file around (otherwise `.env.production` still gets copied).
 */
export function dockerignoreExcludesEnv(content: string, hasOtherEnvFiles: boolean): boolean {
  let excluded = false;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line.startsWith("!")) {
      // `!.env.example` re-includes a template and keeps the exclusion; `!.env` brings the real file back.
      const reIncluded = normalizePattern(line.slice(1));
      if (reIncluded === EXACT_ENV || WILDCARD_ENV.has(reIncluded)) excluded = false;
      continue;
    }
    const pattern = normalizePattern(line);
    if (WILDCARD_ENV.has(pattern) || (pattern === EXACT_ENV && !hasOtherEnvFiles)) excluded = true;
  }
  return excluded;
}

/** Final-stage copies ship in the image; an earlier build stage usually does not. */
export function contextCopyConfidence(copy: ContextCopy, stageCount: number, hasEnvFile: boolean): Confidence {
  if (copy.stage < stageCount - 1) return "low";
  return hasEnvFile ? "high" : "medium";
}
