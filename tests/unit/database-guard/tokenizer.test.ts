import { describe, expect, it } from "vitest";
import {
  balancedInner, parenGroups, splitStatements, splitTopLevel, unquoteIdent,
} from "../../../src/agents/database-guard/sql-tokenizer.js";

describe("splitStatements", () => {
  it("splits on semicolons and tracks the start line", () => {
    const out = splitStatements("select 1;\n\nselect 2;");
    expect(out.map((s) => s.text)).toEqual(["select 1", "select 2"]);
    expect(out.map((s) => s.line)).toEqual([1, 3]);
  });

  it("drops line and nested block comments", () => {
    const out = splitStatements("-- hi; there\nselect /* a /* b; */ c; */ 1; /* open");
    expect(out).toHaveLength(1);
    expect(out[0]?.text.replace(/\s+/g, " ")).toBe("select 1");
  });

  it("does not split on semicolons inside strings and blanks them in the skeleton", () => {
    const out = splitStatements("insert into t values ('a;b', 'it''s');select 2");
    expect(out).toHaveLength(2);
    expect(out[0]?.text).toContain("'a;b'");
    expect(out[0]?.skeleton).not.toContain("a;b");
  });

  it("handles E-strings with backslash escapes", () => {
    const out = splitStatements("select E'a\\';b'; select 2");
    expect(out).toHaveLength(2);
  });

  it("keeps quoted identifiers intact", () => {
    const out = splitStatements('create table "we;ird" (id int);');
    expect(out).toHaveLength(1);
    expect(out[0]?.skeleton).toContain('"we;ird"');
  });

  it("treats dollar-quoted bodies as opaque", () => {
    const sql = "create function f() returns int as $fn$ begin; select 1; end $fn$ language sql; select 3";
    const out = splitStatements(sql);
    expect(out).toHaveLength(2);
    expect(out[0]?.skeleton).not.toContain("select 1");
    expect(out[0]?.text).toContain("select 1");
  });

  it("does not treat $1 or ident$ as dollar quotes", () => {
    const out = splitStatements("select $1; select a$b$c;");
    expect(out).toHaveLength(2);
  });

  it("survives unterminated constructs", () => {
    expect(() => splitStatements("select 'abc")).not.toThrow();
    expect(() => splitStatements('select "abc')).not.toThrow();
    expect(() => splitStatements("select $$abc")).not.toThrow();
    expect(splitStatements("")).toEqual([]);
    expect(splitStatements(";;;")).toEqual([]);
  });
});

describe("helpers", () => {
  it("unquotes identifiers and lowercases unquoted ones", () => {
    expect(unquoteIdent('"My""Tbl"')).toBe("my\"tbl");
    expect(unquoteIdent("Users")).toBe("users");
  });

  it("extracts balanced parens", () => {
    expect(balancedInner("x (a (b) c) d", 2)).toBe("a (b) c");
    expect(balancedInner("x (a", 2)).toBeNull();
  });

  it("splits at top level only", () => {
    expect(splitTopLevel("a, f(b, c), 'd,e', \"x,y\"", ",")).toEqual(["a", "f(b, c)", "'d,e'", '"x,y"']);
  });

  it("finds paren groups", () => {
    expect(parenGroups("(1, 'a)'), (2, 3)")).toEqual(["1, 'a)'", "2, 3"]);
  });
});
