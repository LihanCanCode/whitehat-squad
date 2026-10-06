import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

/** Fake credentials assembled at runtime so no secret-shaped literal is committed. */
export const FAKE_STRIPE_KEY = ["sk", "live", "51H8abcDEF123ghiJKL456mnoPQR789stu"].join("_");

export async function writeTree(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, "utf8");
  }
}

export async function makeTempDir(prefix = "whsquad-"): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

/** A deliberately vulnerable "vibe-coded" Next.js + Supabase app. */
export const VULNERABLE_APP: Record<string, string> = {
  "package.json": JSON.stringify({
    name: "vibe-app",
    dependencies: { next: "14.2.0", react: "18.3.0", "@supabase/supabase-js": "2.45.0", l0dash: "1.0.0", openai: "4.60.0" },
  }),
  "supabase/migrations/001_init.sql":
    "create table public.profiles (id uuid primary key, user_id uuid, email text);\n" +
    "create table public.notes (id serial primary key, user_id uuid, body text);\n",
  ".env": `STRIPE_SECRET_KEY=${FAKE_STRIPE_KEY}\n`,
  "src/app/api/notes/[id]/route.ts":
    'export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n' +
    '  await supabase.from("notes").delete().eq("id", params.id);\n' +
    "  return Response.json({ ok: true });\n}\n",
  "src/components/Chat.tsx":
    '"use client";\nimport OpenAI from "openai";\n' +
    'const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });\n' +
    "export default function Chat() { return null; }\n",
};

/** A well-built app of the same shape. A scan must report nothing above info. */
export const CLEAN_APP: Record<string, string> = {
  "package.json": JSON.stringify({
    name: "clean-app",
    // A patched Next.js: the clean app must not pin a version with published advisories (SUP-010).
    dependencies: { next: "16.3.6", react: "19.2.3", "@supabase/supabase-js": "2.45.0", zod: "3.23.0" },
  }),
  "package-lock.json": JSON.stringify({
    name: "clean-app",
    lockfileVersion: 3,
    packages: {
      "": { name: "clean-app" },
      "node_modules/next": { version: "16.3.6", resolved: "https://registry.npmjs.org/next/-/next-16.3.6.tgz", integrity: "sha512-x" },
    },
  }),
  ".gitignore": ".env\n.env.*\n!.env.example\nnode_modules\n.next\n",
  ".env.example": "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSTRIPE_SECRET_KEY=\n",
  "next.config.js":
    "module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [\n" +
    "      { key: 'Content-Security-Policy', value: \"default-src 'self'\" },\n" +
    "      { key: 'Strict-Transport-Security', value: 'max-age=63072000' },\n" +
    "    ] }];\n  },\n};\n",
  "middleware.ts":
    "import { NextResponse } from 'next/server';\nexport function middleware(req) { return NextResponse.next(); }\n" +
    "export const config = { matcher: ['/dashboard/:path*'] };\n",
  "supabase/migrations/001_init.sql":
    "create table public.notes (id serial primary key, user_id uuid references auth.users, body text);\n" +
    "alter table public.notes enable row level security;\n" +
    "create policy \"own notes\" on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);\n",
  "src/app/api/notes/[id]/route.ts":
    "import { createClient } from '@/lib/supabase/server';\n" +
    "export async function DELETE(req: Request, { params }: { params: { id: string } }) {\n" +
    "  const supabase = await createClient();\n" +
    "  const { data: { user } } = await supabase.auth.getUser();\n" +
    "  if (!user) return new Response('Unauthorized', { status: 401 });\n" +
    "  await supabase.from('notes').delete().eq('id', params.id).eq('user_id', user.id);\n" +
    "  return Response.json({ ok: true });\n}\n",
};
