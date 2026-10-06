import { watch as fsWatch, type FSWatcher } from "node:fs";
import { SKIP_DIRS } from "../core/fs-walk.js";

/** Derived from the walker's skip list so the watcher never reacts to files the scan would not read. */
const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const IGNORE = new RegExp(`(?:^|[\\\\/])(?:${[...SKIP_DIRS].map(escapeRegExp).join("|")})(?:[\\\\/]|$)`);

export function isIgnoredPath(filename: string): boolean {
  return IGNORE.test(filename);
}

type Listener = (event: string, filename: string | null) => void;

export interface FsWatcherOptions {
  /** Called once if the watcher fails; the watcher is already closed when this runs. */
  readonly onError?: (error: Error) => void;
  /** Test seam; defaults to node:fs watch. */
  readonly watchImpl?: (root: string, opts: { recursive?: boolean }, listener: Listener) => FSWatcher;
}

const defaultWatch: NonNullable<FsWatcherOptions["watchImpl"]> = (root, opts, listener) =>
  fsWatch(root, opts, (event, filename) => listener(event, filename === null ? null : String(filename)));

/**
 * Watches a directory tree for changes (ignoring build/VCS noise) and calls onChange on each one.
 * Uses recursive watching where the platform supports it (Windows, macOS); falls back to
 * top-level-only watching elsewhere (most Linux builds), which still catches root-level edits.
 * A watcher 'error' event (deleted root, EPERM, inotify limit) is reported once through onError
 * and stops watching, instead of crashing the process with an unhandled 'error'.
 */
export function createFsWatcher(root: string, onChange: () => void, options: FsWatcherOptions = {}): () => void {
  const watchImpl = options.watchImpl ?? defaultWatch;
  const notify: Listener = (_event, filename) => {
    if (filename && isIgnoredPath(filename)) return;
    onChange();
  };
  let watcher: FSWatcher;
  try {
    watcher = watchImpl(root, { recursive: true }, notify);
  } catch {
    watcher = watchImpl(root, {}, notify);
  }

  let closed = false;
  const close = (): void => {
    if (closed) return;
    closed = true;
    watcher.close();
  };
  watcher.on("error", (e: unknown) => {
    if (closed) return;
    close();
    options.onError?.(e instanceof Error ? e : new Error(String(e)));
  });
  return close;
}
