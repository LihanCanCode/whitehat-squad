import { isGeneratedPath, isTestPath, isVendorPath } from "../../core/source/index.js";
import type { Finding, ScanContext } from "../../core/types.js";
import { corsFindings } from "./static-cors.js";
import { imageConfigFindings, nextHeaderFindings, NEXT_CONFIG, sourceMapFindings } from "./static-config.js";
import { errorLeakFindings } from "./static-errors.js";
import { pathTraversalFindings } from "./static-fs.js";
import { messageListenerFindings, postMessageFindings } from "./static-messages.js";
import { xssFindings } from "./static-xss.js";
import { loadWeb } from "./util.js";
import type { WebFile } from "./util.js";

const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|html?)$/i;
const MAX_FILE_BYTES = 600_000;

/** Reads every scannable file once. Config files are kept even when they live in an ignored/test-looking place. */
async function loadFiles(ctx: ScanContext): Promise<WebFile[]> {
  const files: WebFile[] = [];
  for (const path of ctx.files.paths) {
    if (isVendorPath(path) || isGeneratedPath(path)) continue;
    if (!(CODE_FILE.test(path) || NEXT_CONFIG.test(path))) continue;
    const text = await ctx.files.read(path);
    if (text !== null && text.length <= MAX_FILE_BYTES) files.push(loadWeb(path, text));
  }
  return files;
}

function fileFindings(file: WebFile, target: string): Finding[] {
  const configs = [...sourceMapFindings(file, target), ...imageConfigFindings(file, target)];
  if (isTestPath(file.path)) return configs;
  return [
    ...configs,
    ...corsFindings(file, target),
    ...xssFindings(file, target),
    ...pathTraversalFindings(file, target),
    ...messageListenerFindings(file, target),
    ...postMessageFindings(file, target),
    ...errorLeakFindings(file, target),
  ];
}

export async function runStatic(ctx: ScanContext): Promise<Finding[]> {
  const target = ctx.root ?? ".";
  const files = await loadFiles(ctx);
  const findings: Finding[] = files.flatMap((f) => fileFindings(f, target));
  findings.push(...(await nextHeaderFindings(files, ctx, target)));
  return findings;
}
