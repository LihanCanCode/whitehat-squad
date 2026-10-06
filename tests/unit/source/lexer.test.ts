import { describe, expect, it } from "vitest";
import { createSource } from "../../../src/core/source/lexer.js";
import { lineOf, lineText, snippetAt } from "../../../src/core/source/lines.js";

const lex = (raw: string, path = "a.tsx") => createSource(path, raw);

describe("lexer: invariants", () => {
  const samples = [
    "",
    "const a = 1;",
    "// c\nconst a = `x${`y${1}`}z`; /* m\nn */ const r = /a'b/g;\n",
    'const s = "it\'s"; const t = \'say "hi"\';',
    "return <div>it's {x}</div>;",
    "const x = `unterminated ${",
    'const s = "unterminated\nnext line',
    "/* unterminated",
  ];
  it.each(samples)("keeps length, newlines and offsets for %j", (raw) => {
    const s = lex(raw);
    expect(s.code).toHaveLength(raw.length);
    expect(s.bare).toHaveLength(raw.length);
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === "\n" || raw[i] === "\r") {
        expect(s.code[i]).toBe(raw[i]);
        expect(s.bare[i]).toBe(raw[i]);
      }
    }
  });

  it("exposes path/raw and a lineStarts table", () => {
    const s = lex("a\nb\r\nc");
    expect(s.path).toBe("a.tsx");
    expect(s.raw).toBe("a\nb\r\nc");
    expect(s.lineStarts).toEqual([0, 2, 5]);
  });
});

describe("lexer: comments and strings", () => {
  it("blanks comments in both views, keeps strings in code and blanks them in bare", () => {
    const s = lex('const a = "secret"; // trailing\n/* block\nmore */ const b = 1;');
    expect(s.code).not.toContain("trailing");
    expect(s.code).not.toContain("block");
    expect(s.code).toContain('"secret"');
    expect(s.bare).not.toContain("secret");
    expect(s.bare).toContain('"      "');
    expect(s.bare).toContain("const b = 1;");
  });

  it("handles escapes and the other quote kind inside strings", () => {
    const s = lex(`const a = 'it\\'s // not a comment'; const b = "x\\"y"; const c = 1;`);
    expect(s.bare).toContain("const c = 1;");
    expect(s.code).toContain("// not a comment");
    expect(s.bare).not.toContain("not a comment");
  });

  it("does not let an unterminated string swallow the next line", () => {
    const s = lex('const a = "oops\nconst b = fetch(url);');
    expect(s.bare).toContain("const b = fetch(url);");
  });

  it("treats // inside a string as text", () => {
    const s = lex('const u = "http://x.com"; const k = 2;');
    expect(s.bare).toContain("const k = 2;");
    expect(s.code).toContain("http://x.com");
  });

  it("treats a hashbang as a comment", () => {
    const s = lex("#!/usr/bin/env node\nconst a = 1;");
    expect(s.code).not.toContain("usr");
    expect(s.code).toContain("const a = 1;");
  });
});

describe("lexer: template literals", () => {
  it("keeps ${} expressions as code and blanks template text in bare", () => {
    const s = lex("const q = `select * from t where id = ${userId} and x`;");
    expect(s.bare).not.toContain("select");
    expect(s.bare).toContain("${userId}");
    expect(s.code).toContain("select * from t");
  });

  it("supports nested templates in ${} without ending the outer template early", () => {
    const raw = 'const a = `x ${ cond ? `inner ${deep} text` : "y" } tail`; const after = dangerous(1);';
    const s = lex(raw);
    expect(s.bare).toContain("const after = dangerous(1);");
    expect(s.bare).toContain("${deep}");
    expect(s.bare).not.toContain("tail");
    expect(s.bare).not.toContain("inner");
  });

  it("handles braces and strings inside ${}", () => {
    const s = lex('const a = `v ${ fn({ a: "}" }) } w`; const z = 1;');
    expect(s.bare).toContain("const z = 1;");
    expect(s.bare).not.toContain(" w`");
  });

  it("handles escaped backticks and escaped ${", () => {
    const s = lex("const a = `a \\` b \\${not} c`; const z = 1;");
    expect(s.bare).toContain("const z = 1;");
    expect(s.bare).not.toContain("not");
  });

  it("does not crash on unterminated templates", () => {
    expect(() => lex("const a = `abc ${ x")).not.toThrow();
    expect(() => lex("const a = `abc")).not.toThrow();
  });
});

describe("lexer: regex literals", () => {
  const cases: Array<[string, string]> = [
    ["quote inside regex", "const a = s.replace(/'/g, ''); const z = 1;"],
    ["escaped slash", "const a = x.split(/\\//); const z = 1;"],
    ["backtick inside regex", "const a = /`/.test(s); const z = 1;"],
    ["slash in class", "const a = /[/]'/.test(s); const z = 1;"],
    ["after return", "function f(s) { return /\"/.test(s); } const z = 1;"],
    ["after colon", "const o = { re: /'/ }; const z = 1;"],
    ["after arrow", "const f = (s) => /'/.test(s); const z = 1;"],
    ["after &&", "const a = ok && /\"/.test(s); const z = 1;"],
    ["after typeof/in keywords", "if (typeof x === 'y' && 'a' in /'/) {} const z = 1;"],
    ["quote regex at line start after semicolon", "a();\n/'/.test(s);\nconst z = 1;"],
  ];
  it.each(cases)("%s does not corrupt the rest of the file", (_n, raw) => {
    const s = lex(raw);
    expect(s.bare).toContain("const z = 1;");
  });

  it("blanks the regex body in bare but keeps it in code", () => {
    const s = lex("const r = /auth\\(/g; const z = 1;");
    expect(s.code).toContain("/auth\\(/g");
    expect(s.bare).not.toContain("auth");
    expect(s.bare).toContain("/g");
  });

  it("treats / as division after identifiers, numbers, ) and ]", () => {
    const s = lex("const a = b / 2; const c = (d + e) / 2 / f; const g = h[0] / 3; const k = `${m}/${n}`;");
    expect(s.bare).toContain("b / 2");
    expect(s.bare).toContain("(d + e) / 2 / f");
    expect(s.bare).toContain("h[0] / 3");
  });

  it("treats postfix ++ / -- followed by / as division", () => {
    const s = lex("let i = 0; const a = i++ / 2; const b = j-- / 2; const z = 1;");
    expect(s.bare).toContain("const z = 1;");
    expect(s.bare).toContain("i++ / 2");
  });

  it("does not treat property names that look like keywords as regex starters", () => {
    const s = lex("const a = obj.in / 2 / 3; const z = 1;");
    expect(s.bare).toContain("obj.in / 2 / 3");
  });

  it("falls back to division when a regex would span a line", () => {
    const s = lex("const a = (x) /\nconst z = 1;");
    expect(s.bare).toContain("const z = 1;");
  });

  it("does not treat a closing JSX self-close as a regex", () => {
    const s = lex("const a = <Foo {...p} />; const z = 1;");
    expect(s.bare).toContain("const z = 1;");
  });

  it("handles regex flags and a // that is not a comment inside a regex class", () => {
    const s = lex("const r = /[//]+/gi; const z = 1;");
    expect(s.bare).toContain("const z = 1;");
  });
});

describe("lexer: JSX", () => {
  it("does not let an apostrophe in JSX text swallow the file", () => {
    const s = lex("export default function A() { return <div>it's fine</div>; }\nconst z = fetch(`/api/${id}`);");
    expect(s.bare).toContain("const z = fetch(`     ${id}`);");
    expect(s.bare).not.toContain("fine");
  });

  it("handles // inside JSX text and attribute strings", () => {
    const s = lex('const a = <a href="http://x.y">http://z.w</a>; const z = 1;');
    expect(s.bare).toContain("const z = 1;");
    expect(s.code).toContain("http://z.w");
    expect(s.bare).not.toContain("http");
  });

  it("lexes {expr} children and attributes as code", () => {
    const s = lex("const a = (<div className={`a ${b}`} onClick={() => go('x')}>text {user.name} 'q</div>); const z = 1;");
    expect(s.bare).toContain("${b}");
    expect(s.bare).toContain("user.name");
    expect(s.bare).toContain("const z = 1;");
  });

  it("supports nested elements, fragments and comments in expressions", () => {
    const raw = "const a = <><ul><li>don't {/* it's */ x}</li><li>can't</li></ul></>; const z = 1;";
    const s = lex(raw);
    expect(s.bare).toContain("const z = 1;");
    expect(s.bare).toContain(" x}");
    expect(s.code).not.toContain("it's");
  });

  it("does not treat a less-than comparison as JSX", () => {
    const s = lex("if (a < b && c <d) { x = y; } const z = 1;");
    expect(s.bare).toContain("if (a < b && c <d) { x = y; }");
  });

  it("does not treat TS generics as JSX", () => {
    const s = lex("const m = new Map<string, number>(); const p = useState<string>('x'); const z = 1;", "a.tsx");
    expect(s.bare).toContain("new Map<string, number>()");
    expect(s.bare).toContain("const z = 1;");
  });

  it("recovers when a generic arrow looks like JSX but is never closed", () => {
    const s = lex("const id = <T extends object>(x: T) => x;\nconst msg = \"it's\"; const z = 1;");
    expect(s.bare).toContain("const z = 1;");
    expect(s.bare).toContain("<T extends object>(x: T) => x;");
  });

  it("disables JSX for .ts files", () => {
    const s = lex("const a = <any>x; const z = 1;", "a.ts");
    expect(s.bare).toContain("<any>x; const z = 1;");
  });

  it("handles unterminated JSX without throwing", () => {
    expect(() => lex("const a = <div>oops")).not.toThrow();
    expect(() => lex("const a = <div attr='x")).not.toThrow();
  });
});

describe("lines", () => {
  const s = lex("alpha\n  beta  \r\ngamma");
  it("lineOf is 1-based and binary-searched", () => {
    expect(lineOf(s, 0)).toBe(1);
    expect(lineOf(s, 4)).toBe(1);
    expect(lineOf(s, 5)).toBe(1); // the newline belongs to its own line
    expect(lineOf(s, 6)).toBe(2);
    expect(lineOf(s, s.raw.length - 1)).toBe(3);
    expect(lineOf(s, 9999)).toBe(3);
    expect(lineOf(s, -3)).toBe(1);
  });
  it("lineText returns the line without terminators", () => {
    expect(lineText(s, 1)).toBe("alpha");
    expect(lineText(s, 2)).toBe("  beta  ");
    expect(lineText(s, 3)).toBe("gamma");
    expect(lineText(s, 0)).toBe("");
    expect(lineText(s, 99)).toBe("");
  });
  it("snippetAt trims and truncates", () => {
    expect(snippetAt(s, 8)).toBe("beta");
    const long = lex(`x = "${"a".repeat(300)}"`);
    const snip = snippetAt(long, 0, 50);
    expect(snip).toHaveLength(50);
    expect(snip.endsWith("...")).toBe(true);
    expect(snippetAt(long, 0)).toHaveLength(200);
  });
  it("is fast on many lookups", () => {
    const big = lex("line\n".repeat(200_000));
    const t = Date.now();
    for (let i = 0; i < 200_000; i++) lineOf(big, i * 5);
    expect(Date.now() - t).toBeLessThan(500);
  });
});
