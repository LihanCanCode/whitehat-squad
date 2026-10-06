import type { RuleMeta } from "../../rules/types.js";

const AGENT = "ai-guard";
const MODES = ["static"] as const;

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
export const RULES: readonly RuleMeta[] = [
  {
    id: "AI-001",
    agent: AGENT,
    title: "LLM provider called from browser code",
    severity: "critical",
    cwe: "CWE-798",
    owasp: "LLM10",
    summary:
      "A model provider SDK or API is called from code that ships to the browser, so the API key is visible to every visitor who can then spend your credits or abuse your account.",
    fix: "Move the call behind your own authenticated, rate-limited server route and keep the provider key in a server-only environment variable.",
    modes: MODES,
    tags: ["llm", "secrets"],
  },
  {
    id: "AI-002",
    agent: AGENT,
    title: "User input flows into the system prompt",
    severity: "high",
    cwe: "CWE-77",
    owasp: "LLM01",
    summary:
      "Request-controlled text is concatenated into a system or developer prompt. An attacker can rewrite the model's instructions (prompt injection), leak the prompt or steer tool use.",
    fix: "Keep system prompts static, pass user text only as a user message, and validate or delimit anything untrusted.",
    modes: MODES,
    tags: ["llm", "prompt-injection"],
  },
  {
    id: "AI-003",
    agent: AGENT,
    title: "LLM output used in a dangerous sink",
    severity: "high",
    cwe: "CWE-94",
    owasp: "LLM05",
    summary:
      "Model output reaches eval, a shell, a SQL query, dynamic import, tool dispatch or raw HTML. Because output can be steered by prompt injection, this becomes code execution, SQL injection or XSS.",
    fix: "Treat model output as untrusted input: validate against a schema, use allow-lists for tools and commands, parameterize queries and escape or sanitize markup.",
    modes: MODES,
    tags: ["llm", "injection"],
  },
  {
    id: "AI-004",
    agent: AGENT,
    title: "LLM endpoint has no authentication or rate limiting",
    severity: "high",
    cwe: "CWE-306",
    owasp: "LLM10",
    summary:
      "A public route or action spends model credits with neither authentication nor rate limiting, so anyone can run up your bill or abuse the model through your key.",
    fix: "Require a session, add per-user rate limits and a spending cap on the route that calls the model.",
    modes: MODES,
    tags: ["llm", "abuse"],
  },
  {
    id: "AI-005",
    agent: AGENT,
    title: "LLM call has no output cap or input length limit",
    severity: "medium",
    cwe: "CWE-770",
    owasp: "LLM10",
    summary:
      "A model call has no max output tokens and the user-supplied text is not length-limited, so a single request can consume an unbounded amount of tokens and money.",
    fix: "Set max_tokens (or the provider equivalent) and reject or truncate oversized user input before calling the model.",
    modes: MODES,
    tags: ["llm", "abuse"],
  },
  {
    id: "AI-006",
    agent: AGENT,
    title: "Untrusted content pasted into a tool-enabled prompt",
    severity: "medium",
    cwe: "CWE-77",
    owasp: "LLM01",
    summary:
      "Fetched, retrieved or stored content is pasted undelimited into the prompt of a call that has tools. A hostile document can carry instructions (indirect prompt injection) that make the model invoke those tools.",
    fix: "Delimit untrusted content clearly, strip instructions where possible, and restrict the tools and permissions available to calls that read it.",
    modes: MODES,
    tags: ["llm", "prompt-injection"],
  },
  {
    id: "AI-007",
    agent: AGENT,
    title: "Model API key exposed through a public env var",
    severity: "high",
    cwe: "CWE-798",
    owasp: "LLM02",
    summary:
      "A model provider key is read through a public environment prefix (NEXT_PUBLIC_, VITE_, REACT_APP_). Public variables are inlined into the browser bundle, so the key is exposed (critical when read from client code).",
    fix: "Rename the variable without the public prefix, read it only on the server, and rotate the exposed key.",
    modes: MODES,
    tags: ["llm", "secrets"],
  },
  {
    id: "AI-008",
    agent: AGENT,
    title: "MCP tool passes model-chosen arguments to a dangerous sink",
    severity: "high",
    cwe: "CWE-78",
    owasp: "LLM06",
    summary:
      "An MCP server tool handler uses its arguments as a shell command (critical), outgoing URL, file path or SQL string with no allowlist. The arguments are written by a model that reads untrusted text, so a poisoned document can drive the tool into command execution, SSRF, file access or SQL injection.",
    fix: "Validate tool arguments with enums and allowlists, use execFile with an argument array, confine file paths to one directory, and use parameterised queries.",
    modes: MODES,
    tags: ["llm", "mcp", "injection"],
  },
  {
    id: "AI-009",
    agent: AGENT,
    title: "Vector search is not scoped to the current user or tenant",
    severity: "medium",
    cwe: "CWE-639",
    owasp: "LLM08",
    summary:
      "A similarity search (Pinecone query, Supabase match_* RPC or pgvector SQL) has no user or tenant filter in an app with signed-in users, so one customer's query can retrieve another customer's private documents. Reported with low confidence because some indexes are intentionally shared.",
    fix: "Use a per-user namespace or a metadata filter / WHERE predicate built from the verified session user id.",
    modes: MODES,
    tags: ["llm", "rag", "authorization"],
  },
  {
    id: "AI-010",
    agent: AGENT,
    title: "Agent loop has no step cap",
    severity: "low",
    cwe: "CWE-835",
    owasp: "LLM10",
    summary:
      "A tool-using model call runs in a while(true) or recursive loop with no iteration counter, or with maxSteps / stepCountIs above 20, so a looping or hijacked agent can burn unbounded credits and hammer the tools' backends.",
    fix: "Cap steps (stopWhen: stepCountIs(n) with a small n, or a MAX_STEPS counter) and stop on the first final answer.",
    modes: MODES,
    tags: ["llm", "abuse"],
  },
];
