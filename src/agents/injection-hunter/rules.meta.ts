import type { RuleMeta } from "../../rules/types.js";

const A = "injection-hunter";
const MODES = ["static"] as const;

/** Catalog entries for every rule this agent can raise. Keep in sync with the agent's ruleIds. */
export const RULES: readonly RuleMeta[] = [
  {
    id: "INJ-001",
    agent: A,
    title: "SQL query is built from request data",
    severity: "critical",
    cwe: "CWE-89",
    owasp: "A03",
    summary:
      "Request data (body, query string, route params, form fields) is interpolated or concatenated into the SQL text given to pg, mysql2, sqlite, sequelize, typeorm, knex raw helpers, sql.raw or Prisma $queryRawUnsafe. " +
      "An attacker can append their own SQL and read or change any table the database user can reach. Tagged templates, bound parameters, numeric coercion and allowlisted columns are recognised as safe.",
    fix: "Keep the SQL text constant and pass request values as bound parameters ($1 / ? placeholders, a values array, or prisma.$queryRaw tagged templates). Map sort/column names from a fixed object.",
    modes: MODES,
    tags: ["injection", "sql"],
  },
  {
    id: "INJ-002",
    agent: A,
    title: "Prisma unsafe raw query takes a non-literal query string",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03",
    summary:
      "$queryRawUnsafe / $executeRawUnsafe run an assembled string with no escaping. No request data was seen reaching it, but a runtime-built query is one edit away from SQL injection, so it is flagged for review (medium confidence).",
    fix: "Use the parameterized tagged-template form prisma.$queryRaw`...`, or a literal string with $1.. placeholders and the values passed as extra arguments.",
    modes: MODES,
    tags: ["injection", "sql", "prisma"],
  },
  {
    id: "INJ-003",
    agent: A,
    title: "Request data is placed inside a Supabase (PostgREST) filter string",
    severity: "medium",
    cwe: "CWE-943",
    owasp: "A03",
    summary:
      "supabase-js .or(), .filter() and .textSearch() take a string in PostgREST syntax. When request data is interpolated into it, a visitor can add commas and operators to inject extra conditions and widen the query beyond what the page intended.",
    fix: "Use the typed helpers (.ilike, .eq, .in) or strip , ( ) \" and backslashes from the value before building the filter string.",
    modes: MODES,
    tags: ["injection", "supabase"],
  },
  {
    id: "INJ-004",
    agent: A,
    title: "Shell command is built from request data",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03",
    summary:
      "Request data reaches exec/execSync, or spawn/execa with shell: true or sh -c. Shell metacharacters in the value let an attacker run arbitrary commands on the server. execFile/spawn with an argument array and no shell are not flagged.",
    fix: "Use execFile or spawn with a fixed program and an argument array (no shell), and validate the value against an allowlist or a strict regex.",
    modes: MODES,
    tags: ["injection", "command", "rce"],
  },
  {
    id: "INJ-005",
    agent: A,
    title: "Server fetches a URL chosen by the request (SSRF)",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10",
    summary:
      "fetch, axios, got, ky, undici or http.get is called with a URL whose host (or the whole URL) comes from the request. The attacker can make the server call internal services and cloud metadata endpoints. A fixed origin with request data only in the path or query is not flagged.",
    fix: "Allowlist hosts (parse with new URL, require https, check hostname against a set) or build the URL from a fixed origin plus an encoded id.",
    modes: MODES,
    tags: ["ssrf"],
  },
  {
    id: "INJ-006",
    agent: A,
    title: "Redirect target comes from the request (open redirect)",
    severity: "medium",
    cwe: "CWE-601",
    owasp: "A01",
    summary:
      "redirect(), NextResponse.redirect, res.redirect, router.push or window.location is given a value from next / redirect / returnTo / callbackUrl style parameters. Phishing links on your own domain can bounce users to an attacker's site, including through the ${origin}${next} callback pattern (next=@evil.com).",
    fix: "Allow only same-site relative paths (start with a single /, no //, backslash or @) or an allowlist of hosts, and fall back to a fixed page.",
    modes: MODES,
    tags: ["redirect", "auth"],
  },
  {
    id: "INJ-007",
    agent: A,
    title: "File path is built from request data (path traversal)",
    severity: "high",
    cwe: "CWE-22",
    owasp: "A01",
    summary:
      "readFile, createReadStream, sendFile, download, readdir, stat, writeFile, unlink or rm receives a path derived from the request. ../ sequences escape the intended folder, exposing secrets and source or, for unlink/rm, deleting files (critical). path.basename, a resolve + startsWith check and sendFile root are recognised as guards.",
    fix: "Reduce the value to a file name with path.basename, resolve it against a fixed base directory and reject paths that do not start with that base.",
    modes: MODES,
    tags: ["path", "files"],
  },
  {
    id: "INJ-008",
    agent: A,
    title: "MongoDB filter uses a request value without forcing it to a string (operator injection)",
    severity: "high",
    cwe: "CWE-943",
    owasp: "A03",
    summary:
      "A mongoose/mongodb find, update or delete filter uses a request value directly. A JSON body such as {\"$ne\": null} is an operator, not text, and matches every document, enabling authentication bypass and cross-user data access.",
    fix: "Validate the body with a schema (zod: strings only), wrap values in String(), use $eq, or enable mongoose sanitizeFilter / express-mongo-sanitize.",
    modes: MODES,
    tags: ["injection", "nosql", "mongodb"],
  },
  {
    id: "INJ-009",
    agent: A,
    title: "Request data is executed as code",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03",
    summary:
      "eval, new Function or vm.run* is given text derived from the request. This is remote code execution: the attacker runs JavaScript with the server's privileges and secrets.",
    fix: "Never execute request text. Parse it as data (JSON.parse, a schema, an expression library) or look the operation up in a fixed table of functions.",
    modes: MODES,
    tags: ["injection", "rce", "eval"],
  },
  {
    id: "INJ-010",
    agent: A,
    title: "Dynamic code execution with a non-literal string",
    severity: "medium",
    cwe: "CWE-95",
    owasp: "A03",
    summary:
      "eval, new Function or vm.run* executes a string built at runtime. No request data was traced into it, but any future path from user text to this call is remote code execution, so it is flagged for review (medium confidence).",
    fix: "Replace dynamic execution with data parsing or a lookup of allowed functions.",
    modes: MODES,
    tags: ["eval", "rce"],
  },
];
