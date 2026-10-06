import { describe, expect, it } from "vitest";
import { createSource, handlerUnits, unitHas } from "../../../src/core/source/index.js";

const route = (decl: string) =>
  `export async function GET(req: Request) {\n  ${decl}\n  const rows = await db.notes.findMany({ where: { owner: hint } })\n  return Response.json(rows)\n}\n`;

describe("ownership names come from real code, never from string contents", () => {
  it("does not treat a string mentioning getUser() as an auth-derived value", () => {
    const src = createSource("app/api/notes/route.ts", route('const hint = "await getUser()"'));
    const [unit] = handlerUnits(src);
    expect(unitHas(src, unit!, "ownership")).toBe(false);
  });

  it("still treats a real auth call as auth-derived (control)", () => {
    const src = createSource("app/api/notes/route.ts", route("const hint = (await getUser()).id"));
    const [unit] = handlerUnits(src);
    expect(unitHas(src, unit!, "ownership")).toBe(true);
  });
});

// Code-review regressions: non-identity checks must not count as auth or ownership.
describe("guard names are about the caller's identity", () => {
  const del = (guard: string) =>
    `export async function DELETE(req: Request) {\n  ${guard}\n  const id = new URL(req.url).searchParams.get("id")\n  await db.user.delete({ where: { id } })\n  return Response.json({})\n}\n`;
  const has = (guard: string, name: "auth" | "ownership") => {
    const src = createSource("app/api/users/route.ts", del(guard));
    return unitHas(src, handlerUnits(src)[0]!, name);
  };

  it.each(["await verifyCaptchaToken(body.t)", "verifyCsrfToken(req)", "await validateEmailToken(t)", "checkTokenFormat(t)", "checkRoleName(r)"])(
    "%s is not an auth check",
    (g) => expect(has(g, "auth")).toBe(false),
  );

  it.each(["if (!hasAccessKey(req)) return", "isRoleDefined(r)", "isOwnerless(doc)", "isAuthorizedOrigin(o)", "if (!canDelete()) return"])(
    "%s is not an ownership check",
    (g) => expect(has(g, "ownership")).toBe(false),
  );

  it.each(["await verifyToken(t)", "await requireAuth()", "checkPermissions(user)", "verifyAdminSession(req)"])("control: %s is an auth check", (g) =>
    expect(has(g, "auth")).toBe(true),
  );

  it.each(["if (!canDelete(user, id)) return", "await assertOwner(user, id)", "verifyCurrentUserHasAccessToPost(id)"])(
    "control: %s is an ownership check",
    (g) => expect(has(g, "ownership")).toBe(true),
  );
});
