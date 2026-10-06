/**
 * Generates the deliberately vulnerable demo app used in the video into demo/work/app.
 * It is generated (and gitignored) rather than committed so the fake key below never reaches
 * git history or GitHub secret scanning. Every hole is intentional; nothing here is deployed.
 *
 *   node demo/make-app.mjs
 */
import { randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const app = path.join(here, "work", "app");

/** A random, never-issued key in the Stripe live-key shape: fake by construction. */
function fakeStripeKey() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const body = [...randomBytes(99)].map((b) => alphabet[b % alphabet.length]).join("");
  return `sk_live_51${body}`;
}

const FILES = {
  "package.json": JSON.stringify(
    {
      name: "vibe-notes",
      private: true,
      dependencies: { next: "16.3.6", react: "19.2.1", "@supabase/supabase-js": "2.45.0", openai: "4.60.0" },
    },
    null,
    2,
  ),
  // Committed .env with a live-shaped key and no .gitignore.
  ".env": `# fake key generated for the whitehat-squad demo\nSTRIPE_SECRET_KEY=${fakeStripeKey()}\n`,
  "supabase/migrations/20260101000000_init.sql": `create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  avatar_url text
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  body text
);
alter table public.notes enable row level security;
create policy "notes are readable" on public.notes for select using (true);
`,
  "lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
`,
  "app/api/notes/[id]/route.ts": `import { supabase } from "@/lib/supabase";

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await supabase.from("notes").delete().eq("id", params.id);
  return Response.json({ ok: true });
}
`,
  "app/api/chat/route.ts": `import OpenAI from "openai";
const openai = new OpenAI();

export async function POST(req: Request) {
  const { messages } = await req.json();
  const out = await openai.chat.completions.create({ model: "gpt-4o-mini", messages });
  return Response.json(out.choices[0].message);
}
`,
  "app/api/upload/route.ts": `import { writeFile } from "node:fs/promises";
import path from "node:path";

export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file") as File;
  await writeFile(path.join("uploads", file.name), Buffer.from(await file.arrayBuffer()));
  return Response.json({ ok: true });
}
`,
  // Logic bugs rules cannot see (for `whsquad review`): client-priced checkout, IDOR through a helper.
  "app/actions/orders.ts": `"use server";
import { supabase } from "@/lib/supabase";

export async function placeOrder(form: FormData) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("sign in first");
  const productId = String(form.get("productId"));
  const price = Number(form.get("price"));
  const quantity = Number(form.get("quantity"));
  const total = price * quantity;
  await supabase.from("orders").insert({ user_id: user.id, product_id: productId, quantity, total });
  return { total };
}
`,
  "lib/notes.ts": `import { supabase } from "@/lib/supabase";

export async function getNote(id: string) {
  const { data } = await supabase.from("notes").select("*").eq("id", id).single();
  return data;
}
`,
  "app/api/notes/[id]/share/route.ts": `import { supabase } from "@/lib/supabase";
import { getNote } from "@/lib/notes";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  const note = await getNote(params.id);
  return Response.json(note);
}
`,
};

// Empty the folder rather than deleting it: Windows refuses to remove a directory a shell is sitting in.
mkdirSync(app, { recursive: true });
for (const entry of readdirSync(app)) rmSync(path.join(app, entry), { recursive: true, force: true });
for (const [rel, content] of Object.entries(FILES)) {
  const file = path.join(app, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}
process.stdout.write(`demo app written to ${path.relative(process.cwd(), app)}\n`);
