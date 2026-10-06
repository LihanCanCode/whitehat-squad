import { describe, expect, it } from "vitest";
import {
  PyText, callArgs, isDynamicString, matchBracket, scanPython, statementEnd, withoutLiterals,
} from "../../../src/agents/py-guard/pytext.js";

describe("scanPython masking", () => {
  it("blanks comments and keeps offsets and newlines", () => {
    const src = 'x = 1  # app.run(debug=True)\ny = 2\n';
    const { code } = scanPython(src);
    expect(code.length).toBe(src.length);
    expect(code).not.toContain("debug");
    expect(code.split("\n")).toHaveLength(src.split("\n").length);
    expect(code.startsWith("x = 1")).toBe(true);
  });

  it("blanks single, double, triple, raw and bytes strings but keeps quotes", () => {
    const src = `a = 'eval(x)'\nb = "os.system(y)"\nc = """\nexec(z)\n"""\nd = r"\d+ eval("\ne = b"pickle.loads"\n`;
    const { code, strings } = scanPython(src);
    expect(code).not.toMatch(/eval|exec|pickle|system/);
    expect(strings).toHaveLength(5);
    expect(code.length).toBe(src.length);
  });

  it("does not treat # inside a string as a comment", () => {
    const { code } = scanPython('url = "http://x/#frag"; run(1)\n');
    expect(code).toContain("run(1)");
  });

  it("handles escaped quotes and doubled braces in f-strings", () => {
    const { code, strings } = scanPython('s = f"a \\" {{literal}} {name}"; t = 1\n');
    expect(code).toContain("{name}");
    expect(code).not.toContain("literal");
    expect(code).toContain("t = 1");
    expect(strings[0]?.hasInterp).toBe(true);
  });

  it("keeps f-string expressions as code, including nested quotes and format specs", () => {
    const { code, strings } = scanPython(`q = f"SELECT {request.args['id']:>5} FROM t"\n`);
    expect(code).toContain("request.args['id']");
    expect(strings).toHaveLength(1);
  });

  it("does not mistake identifiers ending in f/r/b for string prefixes", () => {
    const { code, strings } = scanPython('buf = "x"\nself"y"\nrb"z"\n');
    expect(strings.length).toBeGreaterThanOrEqual(2);
    expect(code).toContain("buf");
  });

  it("stops an unterminated single-quote string at end of line", () => {
    const { code } = scanPython("a = 'oops\nb = os.system(c)\n");
    expect(code).toContain("os.system(c)");
  });

  it("handles an unterminated triple-quoted string at EOF", () => {
    const { code } = scanPython('x = """never closed\nhello');
    expect(code).not.toContain("hello");
  });

  it("handles an unclosed f-string field without hanging", () => {
    const { code } = scanPython('x = f"{oops\ny = 1\n');
    expect(code).toContain("y = 1");
  });

  it("keeps nested f-string quotes balanced inside braces", () => {
    const { code } = scanPython(`x = f"{d["k"]} tail"; z = 9\n`);
    expect(code).toContain("z = 9");
  });

  it("unterminated quote inside an f-string field", () => {
    const { code } = scanPython(`x = f"{d['k}"\nz = 1`);
    expect(code).toContain("z = 1");
  });

  it("skips backslash escapes in non-raw strings but not raw ones", () => {
    const { strings } = scanPython('a = "x\\"y"\nb = r"x\\"\n');
    expect(strings[0]?.value).toBe('x\\"y');
    expect(strings[1]?.value).toBe("x\\");
  });
});

describe("PyText", () => {
  const text = new PyText("line1\nline2 # c\r\nline3\n");

  it("maps offsets to 1-based lines using the line table", () => {
    expect(text.lineOf(0)).toBe(1);
    expect(text.lineOf(5)).toBe(1);
    expect(text.lineOf(6)).toBe(2);
    expect(text.lineOf(text.raw.indexOf("line3"))).toBe(3);
  });

  it("returns line text and trims CR", () => {
    expect(text.lineText(2)).toBe("line2 # c");
    expect(text.lineText(99)).toBe("");
    expect(text.lineText(4)).toBe("");
  });

  it("caps snippets at 200 chars", () => {
    const long = new PyText(`x = "${"a".repeat(500)}"`);
    expect(long.snippet(0).length).toBe(200);
  });

  it("supports whsquad-ignore on the same or previous line, only for the named rule", () => {
    const t = new PyText("# whsquad-ignore PY-001, PY-002\napp.run(debug=True)\nother(1)  # whsquad-ignore PY-009\n");
    const a = t.raw.indexOf("app.run");
    expect(t.isSuppressed("PY-001", a)).toBe(true);
    expect(t.isSuppressed("PY-002", a)).toBe(true);
    expect(t.isSuppressed("PY-003", a)).toBe(false);
    expect(t.isSuppressed("PY-009", t.raw.indexOf("other"))).toBe(true);
    expect(t.isSuppressed("PY-009", a)).toBe(false);
  });

  it("finds the string containing an offset", () => {
    const t = new PyText('a = "xy"; b = "z"');
    expect(t.stringAt(t.raw.indexOf('"xy"'))?.value).toBe("xy");
    expect(t.stringAt(t.raw.indexOf("xy") + 1)?.value).toBe("xy");
    expect(t.stringAt(t.raw.indexOf("b"))).toBeUndefined();
    expect(t.stringAt(t.raw.indexOf('"z"'))?.value).toBe("z");
    expect(t.stringAt(0)).toBeUndefined();
  });

  it("handles a large file quickly (10k lines)", () => {
    const big = new PyText("x = 1\n".repeat(10_000));
    expect(big.lineOf(big.raw.length - 1)).toBe(10_000);
  });
});

describe("bracket helpers", () => {
  const code = scanPython('f(a, g(b, c), [1, 2], "s,s", {k: v}) + h(x)').code;

  it("matches brackets and rejects unbalanced input", () => {
    expect(matchBracket(code, code.indexOf("("))).toBe(code.indexOf(" + h"));
    expect(matchBracket("(((", 0)).toBe(-1);
  });

  it("splits top-level call arguments", () => {
    const args = callArgs(code, code.indexOf("("));
    expect(args).toHaveLength(5);
    expect(callArgs("f(", 1)).toEqual([]);
    expect(callArgs("f()", 1)).toEqual([]);
  });

  it("finds statement ends honoring brackets and backslash continuation", () => {
    const src = "x = f(1,\n  2)\ny = 3 + \\n 4\nz = 0";
    expect(src.slice(0, statementEnd(src, 0))).toBe("x = f(1,\n  2)");
    const y = src.indexOf("y");
    expect(src.slice(y, statementEnd(src, y))).toBe("y = 3 + \\n 4");
    expect(statementEnd("a = 1", 0)).toBe(5);
  });
});

describe("string building detection", () => {
  const dyn = (s: string): boolean => {
    const pt = new PyText(s);
    return isDynamicString(pt, 0, s.length);
  };

  it.each([
    'f"SELECT {x}"',
    '"SELECT " + name',
    '"SELECT %s" % name',
    '"SELECT {}".format(name)',
    '"a" "b" + c',
  ])("flags %s", (s) => expect(dyn(s)).toBe(true));

  it.each(['"SELECT 1"', '"a" "b"', '"a" + "b"', "query", 'f"no fields"'])("passes %s", (s) =>
    expect(dyn(s)).toBe(false),
  );

  it("withoutLiterals keeps interpolated f-strings", () => {
    const pt = new PyText('f"x {y}" + "lit"');
    const out = withoutLiterals(pt, 0, pt.raw.length);
    expect(out).toContain("{y}");
    expect(out).not.toContain("lit");
  });
});
