import { createSource } from "../../../src/core/source/lexer.js";

export const src = (path: string, raw: string) => createSource(path, raw);

export const NEXT_ROUTE_PATH = "src/app/api/projects/[id]/route.ts";
export const NEXT_ROUTE = `import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { z } from "zod";

// don't flag: it's a comment with an apostrophe and a "quote
const Body = z.object({ name: z.string().min(1) });
const SLUG = /^[a-z'"\`]+$/;

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await supabase.from("projects").select("*").eq("id", id).eq("user_id", user.id).single();
  return NextResponse.json(data);
}

export const DELETE = async (request: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const url = new URL(request.url);
  const force = url.searchParams.get("force");
  await db.project.delete({ where: { id } });
  return NextResponse.json({ ok: true, force });
};

export async function POST(request: Request) {
  const body = Body.parse(await request.json());
  const raw = await request.json();
  const name = body.name;
  const label = \`project-\${raw.name}\`;
  const n = Number(raw.count);
  return NextResponse.json({ name, label, n });
}

function helper(x: string) {
  return x;
}
`;

export const EXPRESS_PATH = "server/index.js";
export const EXPRESS_APP = `const express = require("express");
const path = require("path");
const app = express();
const router = express.Router();
app.use(express.json());

app.get("/users/:id", async (req, res) => {
  const { id } = req.params;
  const user = await db.query(\`select * from users where id = \${id}\`);
  res.json(user);
});

app.post("/notes", authMiddleware, rateLimit, async (req, res) => {
  const title = req.body.title;
  await db.update({ id });
  res.json({ title });
});

router.delete("/files/:name", function (req, res) {
  const safe = path.basename(req.params.name);
  const filename = "x";
  fs.unlink(safe);
  res.sendStatus(204);
});

app.listen(3000);
`;

export const ACTIONS_PATH = "src/app/actions.ts";
export const ACTIONS = `"use server";
import { auth } from "@/auth";

export async function updateProfile(formData: FormData) {
  const session = await auth();
  const name = formData.get("name");
  const bio = String(formData.get("bio")).trim();
  await db.user.update({ where: { id: session.user.id }, data: { name, bio } });
}

export const deleteAccount = async (userId: string) => {
  await db.user.delete({ where: { id: userId } });
};

async function internalHelper(x: string) {
  return x;
}
const notExported = async () => {};
`;

export const INLINE_ACTION_PATH = "src/app/page.tsx";
export const INLINE_ACTION = `export default function Page() {
  async function save(formData: FormData) {
    "use server";
    await db.insert(formData.get("a"));
  }
  return <form action={save}><input name="a" />it's a form</form>;
}
`;
