import { describe, expect, it } from "vitest";
import {
  classifyFile,
  fileDirectives,
  isGeneratedPath,
  isTestPath,
  isVendorPath,
  routeFromPath,
} from "../../../src/core/source/facts.js";
import { ACTIONS, ACTIONS_PATH, EXPRESS_APP, EXPRESS_PATH, NEXT_ROUTE, NEXT_ROUTE_PATH, src } from "./fixtures.js";

describe("fileDirectives", () => {
  const cases: Array<[string, string, { client: boolean; server: boolean }]> = [
    ["use client first", '"use client";\nimport x from "y";', { client: true, server: false }],
    ["single quotes, no semicolon", "'use client'\nconst a = 1", { client: true, server: false }],
    ["after license comment", '/* (c) */\n// hi\n"use server"\nexport async function a() {}', { client: false, server: true }],
    ["both directives", '"use strict";\n"use client";', { client: true, server: false }],
    ["not at the top", 'import a from "a";\n"use client";', { client: false, server: false }],
    ["inside a string/template", 'const a = "\\"use client\\"";', { client: false, server: false }],
    ["none", "export const a = 1;", { client: false, server: false }],
    ["empty file", "", { client: false, server: false }],
    ["BOM and blank lines first", '﻿\n\n"use server";', { client: false, server: true }],
  ];
  it.each(cases)("%s", (_n, raw, want) => {
    const d = fileDirectives(src("a.ts", raw));
    expect(d.useClient).toBe(want.client);
    expect(d.useServer).toBe(want.server);
  });
});

describe("classifyFile", () => {
  const cases: Array<[string, string, string, string]> = [
    ["next route", "app/api/x/route.ts", "export async function GET() {}", "route"],
    ["next route in src", "src/app/(g)/api/x/route.js", "export const POST = async () => {}", "route"],
    ["pages api", "pages/api/hello.ts", "export default function handler(req, res) {}", "pagesApi"],
    ["src pages api", "src/pages/api/a/b.js", "module.exports = () => {}", "pagesApi"],
    ["server action file", "src/actions/user.ts", '"use server"; export async function a() {}', "action"],
    ["middleware root", "middleware.ts", "export function middleware() {}", "middleware"],
    ["middleware src", "src/middleware.js", "export default function () {}", "middleware"],
    ["proxy.ts", "proxy.ts", "export function proxy() {}", "middleware"],
    ["not a root middleware", "lib/middleware.ts", "export const a = 1", "other"],
    ["express", "server.js", 'const express = require("express"); const app = express(); app.get("/a", (req, res) => res.send(1));', "express"],
    ["hono", "src/index.ts", 'import { Hono } from "hono"; const app = new Hono(); app.get("/", (c) => c.text("x"));', "express"],
    ["express import without routes", "src/lib.ts", 'import express from "express"; export const a = express;', "other"],
    ["use client", "src/components/A.tsx", '"use client"; export default function A() { return null }', "client"],
    ["plain lib", "src/lib/util.ts", "export const a = 1;", "other"],
  ];
  it.each(cases)("%s", (_n, path, raw, kind) => {
    expect(classifyFile(src(path, raw))).toBe(kind);
  });

  it("classifies the shared fixtures", () => {
    expect(classifyFile(src(NEXT_ROUTE_PATH, NEXT_ROUTE))).toBe("route");
    expect(classifyFile(src(EXPRESS_PATH, EXPRESS_APP))).toBe("express");
    expect(classifyFile(src(ACTIONS_PATH, ACTIONS))).toBe("action");
  });

  it("treats a Vite/CRA src tree as client only when told so and the file is not server-ish", () => {
    const s = src("src/pages/Home.tsx", "export default function Home() { return null }");
    expect(classifyFile(s)).toBe("other");
    expect(classifyFile(s, { clientTree: true })).toBe("client");
    expect(classifyFile(src("src/server/db.ts", "export const db = 1"), { clientTree: true })).toBe("other");
    expect(classifyFile(src("src/api/x.ts", 'import fs from "node:fs"; export const a = fs'), { clientTree: true })).toBe("other");
    expect(classifyFile(src("src/App.tsx", 'import fs from "fs"; export const a = 1'), { clientTree: true })).toBe("other");
  });

  it("path wins over a stray use client directive for route files", () => {
    expect(classifyFile(src("app/x/route.ts", '"use client";\nexport async function GET() {}'))).toBe("route");
  });
});

describe("path predicates", () => {
  it.each([
    "tests/a.ts",
    "test/a.ts",
    "src/__tests__/a.ts",
    "src/__mocks__/a.ts",
    "fixtures/a.ts",
    "src/fixture/a.ts",
    "spec/a.ts",
    "e2e/login.ts",
    "src/a.test.ts",
    "src/a.spec.tsx",
    "src\\win\\a.test.js",
    "src/a.test.mjs",
  ])("isTestPath(%s)", (p) => expect(isTestPath(p)).toBe(true));

  it.each(["src/a.ts", "src/latest/a.ts", "src/contest.ts", "src/protest/a.ts", "src/attestation.ts"])("not a test path: %s", (p) =>
    expect(isTestPath(p)).toBe(false),
  );

  it.each(["node_modules/x/a.js", "a/node_modules/x/b.js", "dist/a.js", "build/a.js", ".next/server/a.js", "coverage/a.js", "vendor/a.js", "src/a.d.ts", "public/a.min.js", "src/gen/api.generated.ts", "src/__generated__/x.ts"])(
    "isGeneratedPath/isVendorPath(%s)",
    (p) => expect(isGeneratedPath(p) || isVendorPath(p)).toBe(true),
  );

  it("separates vendor from generated", () => {
    expect(isVendorPath("node_modules/a.js")).toBe(true);
    expect(isVendorPath("src/a.generated.ts")).toBe(false);
    expect(isGeneratedPath("src/a.generated.ts")).toBe(true);
    expect(isGeneratedPath("src/app/page.tsx")).toBe(false);
    expect(isVendorPath("src/app/page.tsx")).toBe(false);
  });
});

describe("routeFromPath", () => {
  it.each([
    ["src/app/api/projects/[id]/route.ts", "/api/projects/[id]"],
    ["app/route.ts", "/"],
    ["app/(marketing)/blog/route.js", "/blog"],
    ["pages/api/hello.ts", "/api/hello"],
    ["src/pages/api/a/index.ts", "/api/a"],
    ["lib/x.ts", undefined],
  ])("%s -> %s", (p, route) => expect(routeFromPath(p)).toBe(route));
});
