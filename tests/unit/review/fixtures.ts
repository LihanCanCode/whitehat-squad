import type { LlmProvider, LlmRequest, LlmResponse } from "../../../src/review/provider.js";
import { HUNTER_SYSTEM } from "../../../src/review/prompts.js";

/** A small app with one logic bug rules cannot see (client-priced order) and an IDOR through a helper. */
export const APP: Record<string, string> = {
  "package.json": '{"dependencies":{"next":"16.3.6","@supabase/supabase-js":"2.45.0"}}',
  "lib/supabase.ts": 'import { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient("u", "k");\n',
  "lib/notes.ts": 'import { supabase } from "@/lib/supabase";\n\nexport async function getNote(id: string) {\n  const { data } = await supabase.from("notes").select("*").eq("id", id).single();\n  return data;\n}\n',
  "app/actions/orders.ts":
    '"use server";\nimport { supabase } from "@/lib/supabase";\n\nexport async function placeOrder(form: FormData) {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) throw new Error("sign in");\n  const price = Number(form.get("price"));\n  const quantity = Number(form.get("quantity"));\n  await supabase.from("orders").insert({ user_id: user.id, total: price * quantity });\n}\n',
  "app/api/notes/[id]/route.ts":
    'import { supabase } from "@/lib/supabase";\nimport { getNote } from "@/lib/notes";\n\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response(null, { status: 401 });\n  return Response.json(await getNote(params.id));\n}\n',
  "components/Button.tsx": '"use client";\nexport default function Button() { return null; }\n',
  ".env": "STRIPE_SECRET_KEY=sk_live_51" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5xY7zA9bC1dE3fG5hJ7kL9mN1pQ3\n",
};

export const PRICE_CANDIDATE = {
  class: "REV-003",
  title: "Order total is computed from a client-supplied price",
  attacker: "any signed-in user",
  input: "a placeOrder form with price=0.01",
  intended_control: "server-side price lookup",
  crossed_boundary: "the client sets what they pay",
  affected_resource: "the shop's revenue",
  result: "buy any product for one cent",
  evidence: [{ file: "app/actions/orders.ts", line: 7, quote: 'const price = Number(form.get("price"));' }],
  severity: "high",
  fix_invariant: "price comes from the products table",
  fix_summary: "Look up the price by productId on the server.",
};

export const CONFIRMED = {
  verdict: "confirmed",
  reason: "price is read from FormData and multiplied into total with no lookup",
  evidence: [{ file: "app/actions/orders.ts", line: 7, quote: 'const price = Number(form.get("price"));' }],
  severity: "high",
  fix_summary: "Fetch the product price server-side.",
  agent_prompt: "In app/actions/orders.ts, load the product's price from the database instead of form data.",
};

/** Scripted provider: hunter answers per unit (matched by file name in the prompt), validator answers in order. */
export class FakeProvider implements LlmProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly requests: LlmRequest[] = [];
  constructor(
    private readonly hunter: (prompt: string) => unknown,
    private readonly validator: (prompt: string) => unknown = () => CONFIRMED,
  ) {}
  async complete(request: LlmRequest): Promise<LlmResponse> {
    this.requests.push(request);
    const isHunter = request.system === HUNTER_SYSTEM;
    return { data: isHunter ? this.hunter(request.prompt) : this.validator(request.prompt), costUsd: 0.01 };
  }
  get hunterCalls(): number {
    return this.requests.filter((r) => r.system === HUNTER_SYSTEM).length;
  }
  get validatorCalls(): number {
    return this.requests.length - this.hunterCalls;
  }
}

/** Hunter that reports the price bug only for the orders unit. */
export const priceHunter = (prompt: string): unknown =>
  prompt.includes("UNIT: action placeOrder") ? { candidates: [PRICE_CANDIDATE], injection_notice: "" } : { candidates: [] };
