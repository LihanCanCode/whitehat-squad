import { describe, expect, it } from "vitest";
import { ids, only, scan } from "./support.js";

const TOKEN = ["npm", "abcdefghijklmnopqrstuvwxyz0123456789"].join("_");

describe("SUP-013 .npmrc hygiene", () => {
  it("flags an http registry, including scoped registries", async () => {
    const { findings } = await scan({ ".npmrc": "registry=http://registry.corp.example/\n@acme:registry=http://npm.acme.example/\n" });
    const f = only(findings, "SUP-013");
    expect(f).toHaveLength(2);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.cwe).toBe("CWE-829");
    expect(f.map((x) => x.evidence[0]?.line).sort()).toEqual([1, 2]);
  });
  it("flags strict-ssl=false in either spelling", async () => {
    for (const line of ["strict-ssl=false", "strict-ssl = false", "strict-ssl=FALSE"]) {
      const { findings } = await scan({ ".npmrc": `${line}\n` });
      expect(only(findings, "SUP-013"), line).toHaveLength(1);
    }
  });
  it("accepts https registries, strict-ssl=true, loopback http registries and comments", async () => {
    const { findings } = await scan({
      ".npmrc": [
        "registry=https://registry.npmjs.org/", "strict-ssl=true", "registry=http://localhost:4873/",
        "# registry=http://old.example/", "; strict-ssl=false", "@a:registry=http://127.0.0.1:4873",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });
  it("flags always-auth with a literal token, and leaves the token itself to SUP-008", async () => {
    const { findings } = await scan({ ".npmrc": `always-auth=true\n//registry.npmjs.org/:_authToken=${TOKEN}\n` });
    expect(only(findings, "SUP-013")).toHaveLength(1);
    expect(only(findings, "SUP-008")).toHaveLength(1);
    expect(JSON.stringify(findings)).not.toContain(TOKEN);
  });
  it("accepts always-auth with an env-var token and a lone always-auth", async () => {
    const a = await scan({ ".npmrc": "always-auth=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n" });
    expect(a.findings).toEqual([]);
    const b = await scan({ ".npmrc": "always-auth=true\n" });
    expect(b.findings).toEqual([]);
  });
  it("ignores a gitignored .npmrc", async () => {
    const { findings } = await scan({ ".gitignore": ".npmrc\n", ".npmrc": "strict-ssl=false\n" });
    expect(findings).toEqual([]);
  });
});

describe("SUP-013 .yarnrc.yml and .yarnrc hygiene", () => {
  it("flags an http npmRegistryServer, also under npmScopes", async () => {
    const yml = [
      'npmRegistryServer: "http://registry.corp.example"', "npmScopes:", "  acme:", "    npmRegistryServer: 'http://npm.acme.example'",
    ].join("\n");
    const { findings } = await scan({ ".yarnrc.yml": yml });
    const f = only(findings, "SUP-013");
    expect(f).toHaveLength(2);
    expect(f.map((x) => x.evidence[0]?.line).sort()).toEqual([1, 4]);
  });
  it("flags enableStrictSsl: false", async () => {
    const { findings } = await scan({ ".yarnrc.yml": "enableStrictSsl: false\n" });
    expect(only(findings, "SUP-013")).toHaveLength(1);
  });
  it("flags yarn classic spellings", async () => {
    const { findings } = await scan({ ".yarnrc": 'registry "http://registry.corp.example"\nstrict-ssl false\n' });
    expect(only(findings, "SUP-013")).toHaveLength(2);
  });
  it("accepts https registries, strict ssl and comments", async () => {
    const { findings } = await scan({
      ".yarnrc.yml": ['npmRegistryServer: "https://registry.yarnpkg.com"', "enableStrictSsl: true", '# npmRegistryServer: "http://x"', "nodeLinker: node-modules"].join("\n"),
    });
    expect(ids(findings)).toEqual([]);
  });
});

describe("SUP-014..017 GitHub Actions", () => {
  const wf = (body: string, path = ".github/workflows/ci.yml") => scan({ [path]: body });

  describe("SUP-014 pull_request_target + PR head checkout", () => {
    const risky = (ref: string, trigger = "pull_request_target") => [
      "name: ci", "on:", `  ${trigger}:`, "    types: [opened]", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:",
      "      - uses: actions/checkout@v4", "        with:", `          ref: ${ref}`, "      - run: npm ci && npm test", "",
    ].join("\n");
    it("flags every head reference form as critical", async () => {
      for (const ref of [
        "${{ github.event.pull_request.head.sha }}", "${{ github.event.pull_request.head.ref }}",
        "${{ github.head_ref }}", "refs/heads/${{ github.event.pull_request.head.ref }}",
      ]) {
        const { findings } = await wf(risky(ref));
        const f = only(findings, "SUP-014");
        expect(f, ref).toHaveLength(1);
        expect(f[0]?.severity).toBe("critical");
        expect(f[0]?.cwe).toBe("CWE-94");
        expect(f[0]?.evidence[0]).toMatchObject({ file: ".github/workflows/ci.yml" });
        expect(f[0]?.evidence[0]?.line).toBe(11);
      }
    });
    it("also flags the inline and list trigger spellings", async () => {
      const inline = risky("${{ github.head_ref }}").replace(/on:\n {2}pull_request_target:\n {4}types: \[opened\]/, "on: pull_request_target");
      expect(only((await wf(inline)).findings, "SUP-014")).toHaveLength(1);
      const list = risky("${{ github.head_ref }}").replace(/on:\n {2}pull_request_target:\n {4}types: \[opened\]/, "on: [push, pull_request_target]");
      expect(only((await wf(list)).findings, "SUP-014")).toHaveLength(1);
    });
    it("flags checkout of the fork repository", async () => {
      const text = risky("main").replace("ref: main", "repository: ${{ github.event.pull_request.head.repo.full_name }}");
      expect(only((await wf(text)).findings, "SUP-014")).toHaveLength(1);
    });
    it("is quiet for pull_request, for base-branch checkouts and for no ref at all", async () => {
      expect(ids((await wf(risky("${{ github.event.pull_request.head.sha }}", "pull_request"))).findings)).not.toContain("SUP-014");
      expect(ids((await wf(risky("${{ github.event.pull_request.base.sha }}"))).findings)).not.toContain("SUP-014");
      expect(ids((await wf(risky("main"))).findings)).not.toContain("SUP-014");
    });
    it("ignores a head ref used by a non-checkout action", async () => {
      const text = risky("x").replace("actions/checkout@v4", "some/other@v1").replace("ref: x", "ref: ${{ github.head_ref }}");
      expect(ids((await wf(text)).findings)).not.toContain("SUP-014");
    });
  });

  describe("SUP-015 script injection in run:", () => {
    const run = (script: string, block = true) => [
      "on: issues", "jobs:", "  j:", "    runs-on: ubuntu-latest", "    steps:",
      block ? "      - run: |" : `      - run: ${script}`, ...(block ? [`          ${script}`] : []), "",
    ].join("\n");
    it("flags untrusted event fields interpolated into a run script", async () => {
      for (const expr of [
        "${{ github.event.issue.title }}", "${{ github.event.issue.body }}", "${{ github.event.pull_request.title }}",
        "${{ github.event.pull_request.head.ref }}", "${{ github.event.comment.body }}", "${{ github.event.review.body }}",
        "${{ github.event.head_commit.message }}", "${{ github.event.head_commit.author.email }}", "${{ github.event.discussion.title }}",
        "${{ github.head_ref }}", "${{ github.event.pull_request.body }}",
      ]) {
        const { findings } = await wf(run(`echo "${expr}"`));
        const f = only(findings, "SUP-015");
        expect(f, expr).toHaveLength(1);
        expect(f[0]?.severity).toBe("high");
        expect(f[0]?.cwe).toBe("CWE-94");
        expect(f[0]?.evidence[0]?.line).toBe(7);
      }
    });
    it("flags the inline run: form with line evidence", async () => {
      const { findings } = await wf(run("echo ${{ github.head_ref }}", false));
      const f = only(findings, "SUP-015");
      expect(f).toHaveLength(1);
      expect(f[0]?.evidence[0]?.line).toBe(6);
    });
    it("flags github-script scripts too", async () => {
      const text = [
        "on: issues", "jobs:", "  j:", "    steps:", "      - uses: actions/github-script@v7", "        with:",
        "          script: |", "            console.log(`${{ github.event.issue.title }}`)", "",
      ].join("\n");
      expect(only((await wf(text)).findings, "SUP-015")).toHaveLength(1);
    });
    it("is quiet when the value goes through env: and is quoted in the script", async () => {
      const safe = [
        "on: issues", "jobs:", "  j:", "    steps:", "      - name: x", "        env:", "          TITLE: ${{ github.event.issue.title }}",
        "          REF: ${{ github.head_ref }}", "        run: |", '          echo "$TITLE" "$REF"', "",
      ].join("\n");
      expect(ids((await wf(safe)).findings)).not.toContain("SUP-015");
    });
    it("is quiet for trusted fields and for expressions outside run scripts", async () => {
      expect(ids((await wf(run('echo "${{ github.event.pull_request.number }} ${{ github.sha }} ${{ github.event.issue.number }} ${{ github.event.pull_request.head.sha }}"'))).findings)).not.toContain("SUP-015");
      const ifOnly = ["on: issues", "jobs:", "  j:", "    steps:", "      - if: contains(github.event.issue.title, 'x')", "        run: echo ok", "      - uses: foo/bar@v1", "        with:", "          title: ${{ github.event.issue.title }}", ""].join("\n");
      expect(ids((await wf(ifOnly)).findings)).not.toContain("SUP-015");
    });
  });

  describe("SUP-016 permissions: write-all", () => {
    it("flags workflow-level and job-level write-all as medium", async () => {
      const top = await wf("on: push\npermissions: write-all\njobs:\n  j:\n    steps:\n      - run: echo\n");
      expect(only(top.findings, "SUP-016")[0]?.severity).toBe("medium");
      expect(only(top.findings, "SUP-016")[0]?.evidence[0]?.line).toBe(2);
      const job = await wf("on: push\njobs:\n  j:\n    permissions: write-all\n    steps:\n      - run: echo\n");
      expect(only(job.findings, "SUP-016")).toHaveLength(1);
    });
    it("accepts least-privilege permissions", async () => {
      const { findings } = await wf("on: push\npermissions:\n  contents: read\njobs:\n  j:\n    permissions: read-all\n    steps:\n      - run: echo\n");
      expect(ids(findings)).not.toContain("SUP-016");
    });
  });

  describe("SUP-017 third-party action pinned to a branch", () => {
    it("flags @main and @master on third-party actions as low", async () => {
      const text = "on: push\njobs:\n  j:\n    steps:\n      - uses: evil/action@main\n      - uses: other/thing@master\n      - uses: 'quoted/action@main'\n";
      const f = only((await wf(text)).findings, "SUP-017");
      expect(f).toHaveLength(3);
      expect(f[0]?.severity).toBe("low");
      expect(f.map((x) => x.evidence[0]?.line).sort()).toEqual([5, 6, 7]);
    });
    it("accepts tags, full SHAs, first-party actions, local and docker actions", async () => {
      const text = [
        "on: push", "jobs:", "  j:", "    steps:", "      - uses: evil/action@v1.2.3",
        "      - uses: evil/action@0123456789abcdef0123456789abcdef01234567", "      - uses: actions/checkout@main",
        "      - uses: github/codeql-action/init@main", "      - uses: ./.github/actions/local", "      - uses: docker://alpine:3.19", "",
      ].join("\n");
      expect(ids((await wf(text)).findings)).not.toContain("SUP-017");
    });
    it("also reads reusable-workflow calls and .yaml files", async () => {
      const text = "on: push\njobs:\n  j:\n    uses: org/repo/.github/workflows/x.yml@main\n";
      expect(only((await wf(text, ".github/workflows/call.yaml")).findings, "SUP-017")).toHaveLength(1);
    });
  });

  it("does not read yaml outside .github/workflows and survives garbage", async () => {
    const outside = await scan({ "docs/ci.yml": "on: pull_request_target\npermissions: write-all\n" });
    expect(outside.findings).toEqual([]);
    const junk = await wf("\t\t::: not yaml [[[\n- - -\n\u0000\n");
    expect(junk.findings).toEqual([]);
  });
  it("a safe, modern workflow produces no findings", async () => {
    const text = [
      "name: CI", "on:", "  push:", "    branches: [main]", "  pull_request:", "permissions:", "  contents: read", "jobs:", "  test:",
      "    runs-on: ubuntu-latest", "    steps:", "      - uses: actions/checkout@v4", "      - uses: actions/setup-node@v4",
      "        with:", "          node-version: 20", "      - run: npm ci", "      - run: npm test", "",
    ].join("\n");
    expect((await wf(text)).findings).toEqual([]);
  });
});
