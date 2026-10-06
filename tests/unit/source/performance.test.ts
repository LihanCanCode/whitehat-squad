import { describe, expect, it } from "vitest";
import { createSource } from "../../../src/core/source/lexer.js";
import { findUnits, handlerUnits } from "../../../src/core/source/units.js";
import { analyzeTaint } from "../../../src/core/source/taint.js";
import { unitHas } from "../../../src/core/source/guards.js";
import { lineOf } from "../../../src/core/source/lines.js";

const BLOCK = (i: number): string => `
// handler ${i}: it's a comment with 'quotes' and "quotes"
export async function handler${i}(req, res) {
  const { id, name } = req.body;
  const re = /['"\`]+\\/x${i}/g;
  const q = \`select * from t${i} where id = \${id} and n = \${name ? \`a\${name}\` : "b"}\`;
  if (id < ${i} && name > 2) { await db.query(q); }
  return res.json({ ok: true, label: "it's ${i}", total: id / 2 / ${i + 1} });
}
const View${i} = () => <div className="x">it's {name} don't</div>;
app.get("/r${i}", auth, async (req, res) => { res.send(req.query.q${i}); });
`;

function synthetic(bytes: number): string {
  const parts: string[] = [];
  let size = 0;
  for (let i = 0; size < bytes; i++) {
    const b = BLOCK(i);
    parts.push(b);
    size += b.length;
  }
  return parts.join("");
}

describe("performance", () => {
  it("lexes and builds units for a ~1 MB synthetic file in < 1.5 s", () => {
    const raw = synthetic(1_000_000);
    expect(raw.length).toBeGreaterThan(1_000_000);
    const t0 = performance.now();
    const s = createSource("big.tsx", raw);
    const lexMs = performance.now() - t0;
    const units = findUnits(s);
    const total = performance.now() - t0;
    // eslint-disable-next-line no-console
    console.log(`1MB synthetic: lex ${lexMs.toFixed(0)} ms, lex+units ${total.toFixed(0)} ms, ${units.length} units`);
    expect(total).toBeLessThan(1500);
    expect(units.length).toBeGreaterThan(2000);
    expect(s.bare).toContain("handler0");
    expect(s.bare).not.toContain("select * from");
    // the file is still structurally intact at the end
    const last = units.filter((u) => u.name.startsWith("handler")).pop()!;
    expect(s.raw.slice(last.end - 1, last.end)).toBe("}");
    expect(lineOf(s, raw.length)).toBe(s.lineStarts.length);
  });

  it("handles a minified-ish one-line file in < 1.5 s", () => {
    const parts: string[] = [];
    for (let i = 0; i < 12000; i++) {
      parts.push(`function f${i}(a,b){var r=/[/'"]x/.test(a)?a/2/${i + 1}:b;return \`t\${r}\`+"s'${i}"}const g${i}=(x)=>x.y(${i});`);
    }
    const raw = parts.join("");
    expect(raw.length).toBeGreaterThan(900_000);
    expect(raw.includes("\n")).toBe(false);
    const t0 = performance.now();
    const s = createSource("min.js", raw);
    const units = findUnits(s);
    const total = performance.now() - t0;
    // eslint-disable-next-line no-console
    console.log(`minified one-line: ${raw.length} chars, lex+units ${total.toFixed(0)} ms, ${units.length} units`);
    expect(total).toBeLessThan(1500);
    expect(units.length).toBe(24000);
    expect(s.lineStarts).toEqual([0]);
  });

  it("taint + guards on a handler inside a large file stay fast", () => {
    const s = createSource("big.tsx", synthetic(400_000));
    const hs = handlerUnits(s);
    expect(hs.length).toBeGreaterThan(100);
    const t0 = performance.now();
    for (const h of hs.slice(0, 50)) {
      analyzeTaint(s, h).taintedNames();
      unitHas(s, h, "auth");
    }
    expect(performance.now() - t0).toBeLessThan(2000);
  });
});
