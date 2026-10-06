import { buildIgnoreMatcher } from "../../src/core/fs-walk.js";
import type {
  FileIndex, HttpResult, SafeHttpClient, ScanContext, StackProfile,
} from "../../src/core/types.js";

/** In-memory FileIndex for tests: keys are root-relative POSIX paths. */
export function memFiles(files: Record<string, string>): FileIndex {
  const ignored = buildIgnoreMatcher(files[".gitignore"] ?? "");
  return {
    paths: Object.keys(files).sort(),
    isIgnored: ignored,
    read: async (p: string) => files[p] ?? null,
  };
}

export const EMPTY_STACK: StackProfile = { frameworks: [], backends: [], routes: [] };

export interface TestContext extends ScanContext {
  readonly secrets: Set<string>;
}

export function memContext(
  files: Record<string, string>,
  overrides: Partial<Pick<ScanContext, "mode" | "target" | "http" | "stack">> = {},
): TestContext {
  const secrets = new Set<string>();
  return {
    mode: "static",
    files: memFiles(files),
    stack: EMPTY_STACK,
    // Backend probing is on here so DatabaseGuard's live rules are testable; the CLI default is off.
    options: { gitHistory: false, maxRequests: 100, probeBackend: true },
    registerSecret: (v: string) => void secrets.add(v),
    secrets,
    ...overrides,
  };
}

export function httpResult(partial: Partial<HttpResult> & { url: string }): HttpResult {
  return { status: 200, headers: {}, setCookies: [], body: "", ...partial };
}

/** Fake read-only client. Unknown URLs return 404. Records every requested URL. */
export function fakeHttp(routes: Record<string, Partial<HttpResult>>): SafeHttpClient & { calls: string[] } {
  const calls: string[] = [];
  const respond = async (url: string): Promise<HttpResult> => {
    calls.push(url);
    const hit = routes[url];
    return hit ? httpResult({ url, ...hit }) : httpResult({ url, status: 404 });
  };
  return { calls, get: respond, head: respond };
}
