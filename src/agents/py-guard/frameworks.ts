import type { ScanContext } from "../../core/types.js";

export type PyFramework = "flask" | "django" | "fastapi";

const MANIFEST = /(?:^|\/)(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|Pipfile|setup\.py|setup\.cfg|poetry\.lock)$/;

const MANIFEST_DEP = /(?:^|[\s"',[])(flask|django|fastapi|starlette)(?=\s*(?:[=<>~![;"',^*]|$))/gim;
const DEP_TO_FRAMEWORK: Readonly<Record<string, PyFramework>> = {
  flask: "flask", django: "django", fastapi: "fastapi", starlette: "fastapi",
};

const IMPORT_HINTS: readonly [PyFramework, RegExp][] = [
  ["flask", /^[ \t]*(?:from|import)[ \t]+flask\b/m],
  ["django", /^[ \t]*(?:from|import)[ \t]+django\b/m],
  ["fastapi", /^[ \t]*(?:from|import)[ \t]+(?:fastapi|starlette)\b/m],
];

/** Frameworks a single Python source file imports. */
export function frameworksInSource(raw: string): Set<PyFramework> {
  const found = new Set<PyFramework>();
  for (const [name, re] of IMPORT_HINTS) if (re.test(raw)) found.add(name);
  return found;
}

/** Frameworks declared in dependency manifests anywhere in the repo. */
export async function frameworksInManifests(ctx: ScanContext): Promise<Set<PyFramework>> {
  const found = new Set<PyFramework>();
  for (const p of ctx.files.paths) {
    if (!MANIFEST.test(p) || /\bnode_modules\//.test(p)) continue;
    const text = await ctx.files.read(p);
    if (text === null) continue;
    for (const m of text.matchAll(MANIFEST_DEP)) {
      const fw = DEP_TO_FRAMEWORK[(m[1] as string).toLowerCase()];
      if (fw) found.add(fw);
    }
  }
  return found;
}
