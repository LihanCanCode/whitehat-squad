import { getLiveAssets } from "../../core/live-assets.js";
import type { Finding, ScanContext } from "../../core/types.js";
import { cookieFindings, headerFindings } from "./live-headers.js";
import {
  FILE_PROBE_COUNT,
  probeCors,
  probeSensitiveFiles,
  probeSourceMaps,
  probeVerboseErrors,
} from "./live-probes.js";

/** Hard cap on requests this agent may cause, including the shared asset crawl. */
export const MAX_LIVE_REQUESTS = 20;
const LANDING_AND_CORS = 2;
const ERROR_PROBE = 1;

export async function runLive(ctx: ScanContext): Promise<Finding[]> {
  const { http, target } = ctx;
  if (!http || !target) return [];
  const b = { http, target };
  const findings: Finding[] = [];

  const landing = await http.get(target.href);
  if (landing.status < 400) {
    findings.push(...headerFindings(landing, target), ...cookieFindings(landing, target));
  }
  findings.push(...(await probeCors(b)));

  // Shared crawl: 1 landing fetch + one per script. Map probes only get what is left.
  const assets = await getLiveAssets(ctx);
  const crawlCost = assets.html ? 1 + assets.scripts.length : 1;
  const reserved = LANDING_AND_CORS + FILE_PROBE_COUNT + ERROR_PROBE;
  const mapBudget = Math.max(0, MAX_LIVE_REQUESTS - reserved - crawlCost);
  findings.push(...(await probeSourceMaps(b, assets.scripts, mapBudget)));

  findings.push(...(await probeSensitiveFiles(ctx, b)));
  findings.push(...(await probeVerboseErrors(b)));
  return findings;
}
