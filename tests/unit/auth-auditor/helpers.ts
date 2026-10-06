import { agent } from "../../../src/agents/auth-auditor/index.js";
import type { Finding } from "../../../src/core/types.js";
import { memContext } from "../../helpers/memfs.js";

export async function scan(files: Record<string, string>): Promise<Finding[]> {
  return agent.run(memContext(files));
}

export function ids(findings: readonly Finding[]): string[] {
  return findings.map((f) => f.ruleId).sort();
}

export async function ruleIdsFor(files: Record<string, string>): Promise<string[]> {
  return ids(await scan(files));
}

/** A middleware that really authenticates (Supabase session) for /dashboard. */
export const MIDDLEWARE = `import { NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
export async function middleware(req: Request) {
  const supabase = createServerClient(process.env.URL!, process.env.KEY!, { cookies: {} });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.redirect(new URL("/login", req.url));
  return NextResponse.next();
}
export const config = { matcher: ["/dashboard/:path*"] };
`;

/** A middleware that does nothing, whatever its matcher says. */
export const NOOP_MIDDLEWARE = `import { NextResponse } from "next/server";
export function middleware(req: Request) { return NextResponse.next(); }
export const config = { matcher: ["/dashboard/:path*"] };
`;
