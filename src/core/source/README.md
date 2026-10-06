# Shared source engine (`src/core/source`)

A dependency-free, deterministic JS/TS/JSX analysis layer for agents. It replaces the per-agent regex
helpers (`stripCode`, `findTemplates`, `handlerUnits`, file-global taint...) with one lexer and a few
structural passes. Think in three steps: **sources -> sinks -> guards**.

```
createSource(path, raw)          one pass: raw / code / bare views + line table
  -> classifyFile / fileDirectives   what kind of file is it?
  -> findUnits / handlerUnits        which functions handle requests?
  -> analyzeTaint(src, unit)         what request data reaches which names? (sources)
  -> your sink regex on unit.bare    where does it go?                      (sinks)
  -> unitHas(src, unit, "auth")      is it protected?                       (guards)
```

## Views

| view       | comments | strings / template text | regex bodies | JSX text | `${...}` expressions |
| ---------- | -------- | ----------------------- | ------------ | -------- | -------------------- |
| `raw`      | kept     | kept                    | kept         | kept     | kept                 |
| `code`     | blanked  | kept                    | kept         | kept     | kept                 |
| `bare`     | blanked  | blanked (quotes kept)   | blanked      | blanked  | **kept as code**     |

All views have the same length and the same newlines, so one offset works everywhere:
`lineOf(src, offset)` (binary search, O(log n)) and `snippetAt(src, offset)` give line / snippet.

Rule of thumb: match **calls and identifiers on `bare`**; match things that need literals (header names,
column names) on `code` but accept a match only when its first character is real code
(`src.bare[i] === src.code[i]`). `guardMatches` already does that.

## API

```ts
createSource(path: string, raw: string, opts?: { jsx?: boolean }): Source
lineOf(src, offset): number; lineText(src, line): string; snippetAt(src, offset, max = 200): string

fileDirectives(src): { useClient; useServer; all }
classifyFile(src, { clientTree? }): "route" | "pagesApi" | "action" | "middleware" | "express" | "client" | "other"
isTestPath(p); isGeneratedPath(p); isVendorPath(p); routeFromPath(p)

findUnits(src): FunctionUnit[]            // every function-like unit, sorted by start, cached
handlerUnits(src): FunctionUnit[]         // request handlers + server actions
unitAt(units, offset): FunctionUnit | undefined   // innermost unit
findRouteRegistrations(src): RouteRegistration[]

analyzeTaint(src, unit, spec?): { isTainted(expr, atOffset?); taintedNames(atOffset?); originOf(name, atOffset?) }
REQUEST_SOURCES, DEFAULT_SANITIZERS

unitHas(src, unit, "auth" | "rateLimit" | "ownership" | "signature" | "validation", { includeRouterMiddleware? })
guardMatches(src, unit, guard, opts?): RegExpExecArray[]   // offsets for reporting
AUTH_CHECK, RATE_LIMIT, OWNERSHIP, SIGNATURE_CHECK, VALIDATION, GUARDS
```

`FunctionUnit`: `{ name, kind: "function"|"arrow"|"method"|"handler", exported, exportedAs?, httpMethod?,
route?, start, end, bodyStart, params, action?, role?, receiver?, extraRanges? }`.

- `start..end` is the whole declaration. For `app.post("/x", auth, handler)` it is the whole call, so
  middleware arguments are inside the unit. When the handler is passed by name, the unit covers the named
  function and the registration is in `extraRanges` (guards scan both).
- `bodyStart` is the `{` of a block body, otherwise the first character of the expression body.
- `params` is the text between the parentheses (from `code`).
- `role` says why it is a handler: `route` (Next `app/**/route.*`, SvelteKit `+server`), `pagesApi`,
  `middleware`, `registration` (Express/Hono/Fastify/Koa), `action` (Server Action).
- A function registered by name appears twice in `findUnits` (the function and the handler);
  `handlerUnits` returns only the handler.

## Worked example: "SQL built from request data" (a sink rule)

```ts
import { analyzeTaint, createSource, handlerUnits, lineOf, matchClose, snippetAt, unitBody, unitHas } from "../../core/source/index.js";

const SQL_SINK = /\b(?:db|pool|client|prisma)\s*\.\s*(?:query|\$queryRawUnsafe|execute)\s*\(/g;

function scan(path: string, raw: string) {
  const src = createSource(path, raw);
  const findings = [];
  for (const unit of handlerUnits(src)) {
    const taint = analyzeTaint(src, unit);               // scoped to THIS unit
    const { bare } = unitBody(src, unit);
    for (const m of bare.matchAll(SQL_SINK)) {
      const open = unit.start + m.index + m[0].length - 1;   // offset of "("
      const close = matchClose(src, open);                    // import from index.js
      const argsCode = src.code.slice(open + 1, close - 1);   // `code` keeps the template text
      if (!taint.isTainted(argsCode, open)) continue;         // ordered: names declared later don't count
      findings.push({
        line: lineOf(src, open),
        snippet: snippetAt(src, open),
        severity: unitHas(src, unit, "auth") ? "medium" : "high",   // guard lowers severity
        origin: taint.originOf(/\w+/.exec(argsCode)?.[0] ?? "", open),
      });
    }
  }
  return findings;
}
```

What the engine does for you here: comments and strings never produce sinks (`bare`), `${id}` inside a
template is seen as code, taint is limited to the handler (no leakage to the next Express route),
destructuring/renames/spreads are followed, `Number(id)` / `schema.parse(x)` clear taint, and the guard
check ignores an outgoing `Authorization:` header or the word `auth()` inside a string.

## Taint model and limits

- Sites: `const/let/var` (multi-declarators, destructuring with nesting/rename/default/rest, type
  annotations), `for..of/in` headers, reassignment (`=`, `+=`, `||=`...), member writes
  (`data.x = tainted` taints `data`), destructuring assignment `({a, b} = req.body)` (single-level),
  array callbacks (`tainted.map(x => ...)` taints `x` inside the callback).
- Ordered: a name is tainted only from the end of its declaring statement. `isTainted(expr, atOffset)`
  answers for that point; without an offset the state at the end of the unit is used (loop and callback
  variables are included).
- Scoped: only module-level sites (outside every unit) plus the unit's own sites are used. `let/const` in a
  nested block end with the block, so a shadowing `const id = "x"` in an inner block does not clean the outer.
- Conditional clearing: a clean reassignment only clears taint if it is at the same or shallower brace depth
  than the tainting assignment, so `if (!q) { q = "default" }` keeps `q` tainted.
- An expression is tainted when it contains a request source, a tainted name (not a property after `.`, not an
  object key), through templates, concatenation, spread, ternaries, `await`, member access, and calls on a
  tainted receiver (`x.trim()`). Calls to **unknown functions do not propagate argument taint** (so
  `db.query(id)` and `lookup(id)` results are clean); known pass-throughs do: `String`, `JSON.parse`,
  `Object.entries/values/keys/assign`, `path.join/resolve`, `decodeURIComponent`, `new URL`, `.concat/.replace/.join`...
- Sanitizers (default: `Number`, `parseInt`, `parseFloat`, `BigInt`, `Boolean`, `encodeURIComponent`,
  `path.basename`, `sanitize*`, `escape*`, and any `.parse/.safeParse/.validate` whose receiver is not
  `JSON`/`Date`/`url`/`path`...) remove the call (including `z.object({...}).parse(x)`) from the expression.
  Pass `extraSanitizers` (additive) or `sanitizers` (replace).
- Seeds: server-action parameters (all), handler first parameter (`req`/`request`, but not `c`/`ctx`/`res`),
  destructured first parameter names like `{ url, params }`, Next route second parameter (`{ params }` or
  `ctx`). Hono/Koa rely on patterns (`c.req.json()`, `ctx.query`) instead of tainting `c`/`ctx`.
- Limits: no inter-procedural flow (a tainted value passed into a helper is not followed), no aliasing through
  object properties other than the root name, no `switch`/loop fix-points, destructuring assignment is only
  matched for a single-level `{}`/`[]`, and `eval`-style dynamic access is ignored.

## Lexer heuristics and limits

- Regex vs division by the previous significant token (regex allowed after `( , = : [ ! & | ? { } ; + - * % < > ~ ^`
  and `return typeof instanceof in of new delete void throw case do else yield await`, or at expression start;
  not after identifiers, numbers, strings, `)` or `]`; postfix `++`/`--` count as values). A regex may not span
  a line, otherwise it is division. Known limit: regex after `)` such as `if (x) /re/.test(y)`.
- Template literals nest arbitrarily; `${...}` content is lexed as code recursively.
- JSX is attempted only in expression position in non-`.ts` files; the tag head is validated and the element
  must close before EOF, otherwise the attempt is rolled back (so TS generic arrows in `.tsx` are mostly safe).
  JSX text is never scanned for quotes or comments. Known limit: `<T extends X>(a) => ...` followed later by
  JSX can still be mis-read in rare layouts.
- Unterminated strings stop at the end of the line; unterminated templates/comments run to EOF without throwing.

## Guards

All guards are regexes over `code` with the "first character is real code" rule, scanned across the unit
range plus `extraRanges`. They are deliberately conservative about what counts as protection:

- `auth`: Supabase `getUser/getClaims/getSession`, `getServerSession`, `auth()`, `currentUser`, Clerk
  `auth.protect`, `jwtVerify`/`jwt.verify`, `getToken`, `verifyIdToken`, `CRON_SECRET` / `Bearer ${secret}`
  compares, wrapper-callback parameter `(req, user) =>`, helper names (`requireUser`, `getCurrentUser`,
  `verifyAdmin`, `assertLoggedIn`, middleware passed by reference `requireAuth`). **Not counted:** an outgoing
  `Authorization` header, `getServerSideProps(`, `checkUserExists(`, `getUserById(`, `getAuthor(`, text in
  strings/comments/regexes.
- `ownership`: `.eq('user_id', user.id)`, `where: { userId: session.user.id }`, `ownerId: currentUser.id`,
  `{ userId: userId }` / `{ userId }` when `userId` was declared from an auth call in the same unit, post-fetch
  `!== user.id`, `verify*Access*` / `canEdit` / `isOwner` helpers.
- `rateLimit`, `signature` (constructEvent, createHmac, timingSafeEqual, `new Webhook(`, verifySignature...),
  `validation` (zod/yup/valibot `.parse/.safeParse/.validate`, `zValidator`, `validationResult`).
- Router-level middleware (`app.use(auth)` before the route) only counts with
  `{ includeRouterMiddleware: true }`; Next.js `middleware.ts` coverage is the caller's job.

## Performance

`createSource` + `findUnits` handle ~1 MB in well under 150 ms (single pass, O(1) bracket matching table,
O(log n) line lookup, whole-file taint sites computed once per `Source`). All results are cached per `Source`
object (WeakMap), so re-use the same `Source` across rules.
