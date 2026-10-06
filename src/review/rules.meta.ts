import type { RuleMeta } from "../rules/types.js";

const A = "ai-review";
const MODES = ["static"] as const;

/**
 * Attack classes for `whsquad review` (opt-in, LLM-assisted). Each finding names a crossed trust boundary
 * and a concrete result; AI findings never affect the exit code and are labelled with the model used.
 */
export const RULES: readonly RuleMeta[] = [
  {
    id: "REV-001", agent: A, title: "Broken object-level authorization (IDOR / cross-tenant access)", severity: "high", cwe: "CWE-639", owasp: "A01",
    summary: "AI review traced a request that reads or changes another user's or tenant's record because the id comes from the caller and no ownership or tenant check applies on that path, including checks that exist in some handlers but not this one.",
    fix: "Derive the owner or tenant from the session and filter by it (or enforce it in RLS) on every path to the record.",
    modes: MODES, tags: ["ai", "authz"],
  },
  {
    id: "REV-002", agent: A, title: "Missing function-level authorization (role or plan check)", severity: "high", cwe: "CWE-285", owasp: "A01",
    summary: "AI review found an action reserved for admins, owners or a paid plan that any signed-in (or anonymous) caller can trigger, often because the check exists only in the UI.",
    fix: "Check the caller's role or plan on the server at the top of the handler, from the session or database, never from the request.",
    modes: MODES, tags: ["ai", "authz"],
  },
  {
    id: "REV-003", agent: A, title: "Business logic can be abused (price, quantity, coupon or state)", severity: "high", cwe: "CWE-840", owasp: "A04",
    summary: "AI review found a flow where client-controlled values decide money, limits or state transitions: amounts or prices from the request, reusable coupons, negative quantities, or steps that can be skipped.",
    fix: "Compute prices, limits and transitions on the server from trusted data and validate each state change against the current state.",
    modes: MODES, tags: ["ai", "business-logic"],
  },
  {
    id: "REV-004", agent: A, title: "Race condition or double-spend on a check-then-act path", severity: "medium", cwe: "CWE-367", owasp: "A04",
    summary: "AI review found a balance, stock, quota or one-time token that is read, checked and written in separate steps, so concurrent requests can pass the check twice.",
    fix: "Make the check and the write one atomic operation (a conditional UPDATE, a transaction with row locks, or a unique constraint).",
    modes: MODES, tags: ["ai", "concurrency"],
  },
  {
    id: "REV-005", agent: A, title: "Server trusts identity or privileged fields sent by the client", severity: "high", cwe: "CWE-602", owasp: "A01",
    summary: "AI review found a handler that takes userId, role, ownerId, isAdmin or similar from the request body, query or headers and acts on it instead of the authenticated session.",
    fix: "Ignore identity and privilege fields from the request; read them from the verified session and allow-list writable fields.",
    modes: MODES, tags: ["ai", "authn"],
  },
  {
    id: "REV-006", agent: A, title: "Request data reaches a dangerous sink through a helper", severity: "high", cwe: "CWE-74", owasp: "A03",
    summary: "AI review followed request data across files into SQL, a shell, a URL fetch, a file path or HTML, where the helper in another module does no escaping or validation (single-file rules cannot see this).",
    fix: "Validate at the boundary and use the safe API at the sink (parameterised queries, execFile argument arrays, URL allow-lists, path containment, escaping).",
    modes: MODES, tags: ["ai", "injection"],
  },
  {
    id: "REV-007", agent: A, title: "Webhook, callback or redirect is trusted without verification", severity: "high", cwe: "CWE-345", owasp: "A08",
    summary: "AI review found a webhook, OAuth/payment callback or return URL whose payload or parameters are acted on (grant access, mark paid) without verifying the signature, state or amount with the provider.",
    fix: "Verify the provider signature or state, then re-fetch the authoritative object from the provider before acting.",
    modes: MODES, tags: ["ai", "integrity"],
  },
  {
    id: "REV-008", agent: A, title: "AI feature can be steered into a privileged action", severity: "high", cwe: "CWE-1427", owasp: "LLM01",
    summary: "AI review found model output or user-controlled prompt content that drives tools, database writes, emails or other privileged actions without an allow-list or confirmation step.",
    fix: "Treat model output as untrusted input: allow-list actions and arguments, scope them to the caller, and require confirmation for side effects.",
    modes: MODES, tags: ["ai", "llm"],
  },
  {
    id: "REV-009", agent: A, title: "Other trust-boundary violation found by AI review", severity: "medium", cwe: "CWE-693", owasp: "A04",
    summary: "AI review found a concrete boundary violation outside the classes above. It still names the attacker, the crossed control and the result.",
    fix: "Enforce the stated invariant at the last trusted decision point, then re-check with `whsquad review --recheck`.",
    modes: MODES, tags: ["ai"],
  },
];

export const REVIEW_CLASS_IDS = RULES.map((r) => r.id);
