import { agent } from "../../../src/agents/supply-chain/index.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext } from "../../helpers/memfs.js";

export const pkg = (deps: Record<string, string>, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps, ...extra }, null, 2);

export const npmLock = (pkgs: Record<string, Record<string, unknown>>): string =>
  JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, ...pkgs } });

export const good = { version: "1.0.0", resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz", integrity: "sha512-abc" };

export async function scan(files: Record<string, string>) {
  const ctx = memContext(files);
  return { findings: await agent.run(ctx), ctx };
}

export const ids = (f: readonly Finding[]): string[] => f.map((x) => x.ruleId);
export const only = (f: readonly Finding[], ruleId: string): Finding[] => f.filter((x) => x.ruleId === ruleId);
