import type { Confidence } from "../../core/types.js";
import type { Hit } from "./util.js";

export interface Raised extends Hit {
  /** Selects a sub-variant of the rule's wording (e.g. "AUTH-004:none"). */
  readonly variant?: string;
  readonly confidence?: Confidence;
  /** Instance-specific sentence appended to the rule explanation (target table, names...). */
  readonly note?: string;
}
