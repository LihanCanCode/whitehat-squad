export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Mode = "static" | "live";

export interface Evidence {
  readonly file?: string;
  readonly line?: number;
  readonly url?: string;
  /** Always redacted before it reaches a reporter. */
  readonly snippet: string;
}

export interface Fix {
  readonly summary: string;
  readonly patch?: { readonly file: string; readonly diff: string };
  readonly sql?: string;
  readonly config?: string;
  /** Paste-ready prompt for Claude Code / Cursor / Lovable / Bolt. */
  readonly agentPrompt: string;
  readonly references: readonly string[];
}

export interface Finding {
  readonly id: string;
  readonly ruleId: string;
  readonly agentId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Plain English: what is wrong, why it matters, who can exploit it. */
  readonly explanation: string;
  readonly evidence: readonly Evidence[];
  readonly fix: Fix;
  readonly verify: { readonly command: string; readonly ruleId: string; readonly target: string };
  readonly cwe?: string;
  /** True when this finding was already present in the baseline file: shown, but never fails the build. */
  readonly baseline?: boolean;
  /** Set only by `whsquad review`: produced by an LLM, never affects the exit code. */
  readonly origin?: "ai";
  /** AI findings: the model that produced and validated it. */
  readonly reviewModel?: string;
  /** AI findings: confirmed by an independent validator, or a source-grounded hypothesis needing a human check. */
  readonly reviewState?: "confirmed" | "needs_validation";
  /** AI findings: the review unit (handler, action or database policies) it was found in. */
  readonly reviewUnit?: string;
}

export type FrameworkName = "next" | "vite" | "react" | "remix" | "express";
export type BackendName = "supabase" | "firebase" | "stripe" | "openai" | "anthropic";

export interface StackProfile {
  frameworks: FrameworkName[];
  backends: BackendName[];
  supabaseUrl?: string;
  anonKey?: string;
  firebaseProjectId?: string;
  routes: string[];
}

export interface FileIndex {
  /** Root-relative POSIX paths of every scannable file. */
  readonly paths: readonly string[];
  /** True when the file cap was hit and some files were never scanned. */
  readonly truncated?: boolean;
  /** Returns file text, or null if unreadable, binary or over the size cap. */
  read(relPath: string): Promise<string | null>;
  /** Cumulative counters for the coverage block. Absent on synthetic indexes (tests, live scans). */
  stats?(): FileStats;
  /** True if the root .gitignore would ignore this path. */
  isIgnored(relPath: string): boolean;
}

export interface FileStats {
  /** Files whose text was successfully returned by read(). */
  readonly read: number;
  /** Files skipped because they exceed the size cap. */
  readonly skippedLarge: number;
  /** Files skipped as binary (by extension while walking, or by content when read). */
  readonly skippedBinary: number;
}

export interface HttpResult {
  readonly url: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly setCookies: readonly string[];
  readonly body: string;
}

/** Read-only HTTP client. Only GET/HEAD/OPTIONS exist by construction. */
export interface SafeHttpClient {
  get(url: string, opts?: { headers?: Record<string, string>; maxBytes?: number }): Promise<HttpResult>;
  head(url: string, opts?: { headers?: Record<string, string> }): Promise<HttpResult>;
}

export interface ScanOptions {
  gitHistory: boolean;
  maxRequests: number;
  /** Live mode only: let DatabaseGuard read at most one row per table from the site's Supabase/Firestore backend. */
  probeBackend?: boolean;
}

export interface ScanContext {
  readonly mode: Mode;
  readonly root?: string;
  readonly target?: URL;
  readonly files: FileIndex;
  readonly stack: StackProfile;
  readonly http?: SafeHttpClient;
  readonly options: ScanOptions;
  /** Agents register every raw secret they see so the orchestrator can scrub reports. */
  registerSecret(value: string): void;
}

export interface Agent {
  readonly id: string;
  readonly name: string;
  readonly role: string;
  readonly modes: readonly Mode[];
  run(ctx: ScanContext): Promise<Finding[]>;
}

/** What a scan actually looked at, so "no findings" can say what was checked. */
export interface Coverage {
  readonly filesIndexed: number;
  readonly filesRead: number;
  readonly filesSkippedLarge: number;
  readonly filesSkippedBinary: number;
  readonly truncated: boolean;
  readonly agentsRun: number;
  readonly rulesInCatalog: number;
  readonly durationMs: number;
  /** Live scans only: HTTP requests the scan sent. */
  readonly liveRequests?: number;
}

export interface SuppressedFinding {
  readonly id: string;
  readonly ruleId: string;
  readonly file?: string;
  readonly line?: number;
  readonly reason?: string;
}

export type RuleOverride = "off" | Severity;

/** The configuration a scan ran with (config file merged with CLI flags). */
export interface ReportConfig {
  /** Config file path the scan used, as printed to the user. */
  readonly source?: string;
  readonly failOn?: Severity;
  readonly ignorePaths: readonly string[];
  /** Rule id or prefix wildcard -> "off" or a severity override. */
  readonly rules: Readonly<Record<string, RuleOverride>>;
  readonly only: readonly string[];
  readonly exclude: readonly string[];
  readonly baseline?: string;
  /** Findings removed or changed by the policy, so nothing disappears silently. */
  readonly applied: {
    readonly ignoredByPath: number;
    readonly ruleOff: number;
    readonly severityOverridden: number;
    readonly filteredByPrefix: number;
  };
}

/** Options of the original scan, persisted so `verify` re-runs the same scan. */
export interface PersistedScanOptions {
  readonly gitHistory: boolean;
  readonly probeDatabase: boolean;
  readonly allowPrivate: boolean;
}

/** One ordered unit of the fix plan: a group of findings that share a root cause. */
export interface RemediationStep {
  /** "step-1", "step-2", ... in plan order. */
  readonly id: string;
  /** 1-based priority phase (1 = rotate leaked secrets ... 7 = hardening). */
  readonly phase: number;
  readonly phaseName: string;
  readonly title: string;
  readonly severityMax: Severity;
  readonly ruleIds: readonly string[];
  readonly findingIds: readonly string[];
  /** Unique evidence files, sorted. */
  readonly files: readonly string[];
  readonly summary: string;
  readonly sql?: string;
  /** Shell commands to run (e.g. npm install ...). */
  readonly commands?: readonly string[];
  /** One paste-ready prompt for the whole step. */
  readonly agentPrompt: string;
}

export interface RemediationPlan {
  readonly steps: readonly RemediationStep[];
  /** Finding ids kept out of the plan: known (baseline) or low-confidence. Validate these first. */
  readonly review: readonly string[];
  /** Every step's SQL merged into one migration. */
  readonly migrationSql?: string;
  /** One prompt that works through every step in order. */
  readonly masterPrompt: string;
}

export interface ScanReport {
  readonly schemaVersion: 1;
  readonly tool: "whitehat-squad";
  readonly version: string;
  readonly target: string;
  readonly mode: Mode;
  readonly startedAt: string;
  readonly stack: StackProfile;
  readonly agents: readonly { id: string; name: string; findings: number; error?: string }[];
  readonly findings: readonly Finding[];
  /** Findings hidden by an inline `whsquad-ignore` directive. */
  readonly suppressed?: readonly SuppressedFinding[];
  readonly coverage?: Coverage;
  readonly config?: ReportConfig;
  /** Set by the CLI so `verify` can repeat the scan with the same flags. */
  readonly scanOptions?: PersistedScanOptions;
  /** Set by the CLI after the scan (never by the orchestrator): the ordered fix plan. */
  readonly remediation?: RemediationPlan;
}
