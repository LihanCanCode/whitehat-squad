import type { FileCtx, Project } from "./context.js";
import type { Raised } from "./report-types.js";
import { insecureAuthTokens, hostHeaderLinks } from "./rules-cookies.js";
import { weakPasswordHandling, weakRandomness } from "./rules-crypto.js";
import { unthrottledAuthEndpoints } from "./rules-ops.js";
import { dangerousLinking, getSessionAuthz, invertedAuthCheck, userMetadataAuthz } from "./rules-session.js";
import { massAssignment, paymentTampering, unverifiedSuccessPage } from "./rules-write.js";

export type RulePass = (f: FileCtx, project: Project) => Raised[];

/** Passes for AUTH-008 and later (AUTH-015 is run separately because it supersedes AUTH-002). */
export const NEW_RULE_PASSES: readonly RulePass[] = [
  (f) => getSessionAuthz(f),
  (f) => userMetadataAuthz(f),
  massAssignment,
  (f) => paymentTampering(f),
  (f) => unverifiedSuccessPage(f),
  (f) => weakRandomness(f),
  (f) => weakPasswordHandling(f),
  unthrottledAuthEndpoints,
  (f) => invertedAuthCheck(f),
  (f) => insecureAuthTokens(f),
  (f) => dangerousLinking(f),
  (f) => hostHeaderLinks(f),
];
