import { promises as fs } from "node:fs";
import path from "node:path";

export class UnsafeWriteError extends Error {}

/**
 * Refuses a write into a scanned repository when the target, or any existing directory between the
 * root and it, is a symlink or junction. A hostile repo could otherwise point `.whsquad/`,
 * `supabase/migrations/` or `.gitignore` at a file outside the project (e.g. ~/.bashrc) and have
 * `whsquad fix --write` append to it. Components that do not exist yet are fine: mkdir creates real
 * directories. The target must also resolve inside the root.
 */
export async function assertSafeTarget(root: string, target: string): Promise<void> {
  const base = path.resolve(root);
  const full = path.resolve(base, target);
  const rel = path.relative(base, full);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new UnsafeWriteError(`refusing to write ${target}: it is outside ${base}`);
  }
  let current = base;
  for (const part of rel.split(path.sep)) {
    current = path.join(current, part);
    const stat = await fs.lstat(current).catch((e: NodeJS.ErrnoException) => {
      if (e.code === "ENOENT") return null;
      throw e;
    });
    if (stat === null) return;
    if (stat.isSymbolicLink()) {
      throw new UnsafeWriteError(`refusing to write through ${path.relative(base, current)}: it is a symbolic link`);
    }
  }
}
