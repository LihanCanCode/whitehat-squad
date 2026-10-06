import { describe, expect, it } from "vitest";
import { expectNoRawSecrets, fake, SAMPLES, scan } from "./fakes.js";

async function ids(files: Record<string, string>): Promise<string[]> {
  return (await scan(files)).findings.map((f) => f.ruleId);
}
const only = async (id: string, files: Record<string, string>) =>
  (await scan(files)).findings.filter((f) => f.ruleId === id);

describe("SEC-110 weak or fallback application secrets", () => {
  it("flags a known-weak value in an env file as high, without echoing it", async () => {
    const { findings, ctx } = await scan({ ".env.production": "JWT_SECRET=changeme\n", ".gitignore": ".env.production\n" });
    const hit = findings.find((f) => f.ruleId === "SEC-110");
    expect(hit).toMatchObject({ severity: "high", cwe: "CWE-798", agentId: "secrets-hunter" });
    expect(hit?.evidence[0]).toMatchObject({ file: ".env.production", line: 1 });
    expect(hit?.evidence[0]?.snippet).not.toContain("changeme");
    expect(hit?.title).toContain("JWT_SECRET");
    expect(ctx.secrets.has("changeme")).toBe(true);
  });

  it("ignores examples in JS comments (self-scan regression), still flags the code line", async () => {
    const code = '/** e.g. `process.env.JWT_SECRET || "fallback"` */\n// const AUTH_SECRET = "changeme";\nconst s = process.env.JWT_SECRET || "fallback";\n';
    const hits = await only("SEC-110", { "src/auth.ts": code });
    expect(hits.map((h) => `${h.evidence[0]?.file}:${h.evidence[0]?.line}`)).toEqual(["src/auth.ts:3"]);
  });

  it("flags short literals, digit-only values and repeated characters", async () => {
    const files = {
      ".env.local": `NEXTAUTH_SECRET=abc123def456\nAUTH_SECRET=${"1234567890".repeat(4)}\nSESSION_SECRET=${fake(40)}\n`,
    };
    const hits = await only("SEC-110", files);
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([1, 2]);
  });

  it("flags code assignments and literal fallbacks, even long ones", async () => {
    const longFallback = fake(40);
    const { findings, ctx } = await scan({
      "src/auth.ts": [
        `export const JWT_SECRET = "secret";`,
        `const a = process.env.SESSION_SECRET || "dev";`,
        `const b = process.env["COOKIE_SECRET"] ?? 'my-cookie-secret';`,
        `const c = process.env.NEXTAUTH_SECRET || "${longFallback}";`,
        `const cfg = { appSecret: "tiny" };`,
      ].join("\n"),
    });
    const hits = findings.filter((f) => f.ruleId === "SEC-110");
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([1, 2, 3, 4, 5]);
    expect(hits[3]?.explanation).toMatch(/fallback/i);
    expect(ctx.secrets.has(longFallback)).toBe(true);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
  });

  it("is never a finding for placeholders in .env templates", async () => {
    expect(await ids({
      ".env.example": "JWT_SECRET=changeme\nAUTH_SECRET=your-secret-here\nSECRET_KEY=secret\n",
      ".env.sample": "NEXTAUTH_SECRET=test\n",
    })).toEqual([]);
  });

  it("ignores strong values, env reads, references, empty values and unrelated names", async () => {
    expect(await ids({
      ".env.local": `JWT_SECRET=${fake(40)}\nAPP_SECRET=\nSESSION_SECRET=\${SESSION_FROM_VAULT}\nSTRIPE_SECRET_KEY=short\nOAUTH_SECRET=abc\n`,
      ".gitignore": ".env.local\n",
      "src/a.ts": [
        `const JWT_SECRET = process.env.JWT_SECRET;`,
        `const s = process.env.JWT_SECRET || "";`,
        `if (JWT_SECRET === "secret") throw new Error("no");`,
        `const oauthSecret = "abc";`,
        `const stripeSecretKey = "short";`,
        `const t = process.env.AUTH_SECRET ?? process.env.OTHER;`,
        "const u = `${process.env.JWT_SECRET}`;",
      ].join("\n"),
    })).toEqual([]);
  });

  it("downgrades a doc or test file to low confidence but still reports it", async () => {
    const { findings } = await scan({ "docs/setup.md": 'JWT_SECRET="secret"\n', "tests/a.test.ts": `const JWT_SECRET = "secret";\n` });
    const hits = findings.filter((f) => f.ruleId === "SEC-110");
    expect(hits).toHaveLength(2);
    expect(hits.every((h) => h.confidence === "low")).toBe(true);
  });

  it("also applies inside compose and workflow env blocks", async () => {
    const hits = await only("SEC-110", {
      "docker-compose.yml": "services:\n  api:\n    environment:\n      - JWT_SECRET=changeme\n",
      ".github/workflows/ci.yml": "jobs:\n  t:\n    env:\n      AUTH_SECRET: secret\n",
    });
    expect(hits.map((h) => h.evidence[0]?.file).sort()).toEqual([".github/workflows/ci.yml", "docker-compose.yml"]);
  });

  it("replaces the generic SEC-090 duplicate for the same value", async () => {
    const value = fake(28) + "9";
    const { findings } = await scan({ "src/a.ts": `const sessionSecret = "${value}";\n` });
    expect(findings.map((f) => f.ruleId)).toEqual(["SEC-110"]);
  });
});

describe("SEC-111 literal secrets in compose, workflows, Dockerfiles and .properties", () => {
  const value = fake(24) + "9";

  it("flags map and list forms inside compose environment blocks as medium/medium", async () => {
    const { findings, ctx } = await scan({
      "docker-compose.prod.yml": [
        "services:",
        "  db:",
        "    environment:",
        `      POSTGRES_PASSWORD: ${value}`,
        "  api:",
        "    environment:",
        `      - API_TOKEN=${value}x`,
      ].join("\n"),
    });
    const hits = findings.filter((f) => f.ruleId === "SEC-111");
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([4, 7]);
    expect(hits.every((h) => h.severity === "medium" && h.confidence === "medium" && h.cwe === "CWE-798")).toBe(true);
    expect(hits[0]?.evidence[0]?.snippet).not.toContain(value);
    expect(expectNoRawSecrets(findings, ctx)).toEqual([]);
    expect(ctx.secrets.has(value)).toBe(true);
  });

  it("flags GitHub workflow env literals but not secrets context", async () => {
    const hits = await only("SEC-111", {
      ".github/workflows/deploy.yml": [
        "env:",
        "  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
        `  VENDOR_API_KEY: ${value}`,
        "jobs:",
        "  b:",
        "    steps:",
        "      - run: echo hi",
        "        env:",
        `          SERVICE_PASSWORD: ${value}2`,
      ].join("\n"),
    });
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([3, 9]);
  });

  it("flags Dockerfile ENV and ARG literals for secret-ish names only", async () => {
    const hits = await only("SEC-111", {
      Dockerfile: [
        "FROM node:20",
        "ENV NODE_ENV=production PORT=3000",
        `ENV INTERNAL_API_KEY=${value}`,
        `ARG REGISTRY_PASSWORD=${value}1`,
        `ENV LEGACY_SECRET ${value}2`,
        "ARG BUILD_TOKEN",
        "COPY package.json ./",
      ].join("\n"),
      ".dockerignore": ".env*\n",
    });
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([3, 4, 5]);
  });

  it("flags secret-ish keys in .properties files", async () => {
    const hits = await only("SEC-111", {
      "src/main/resources/application.properties": `app.name=demo\nspring.datasource.password=${value}\n# api.key=${value}1\n`,
    });
    expect(hits.map((h) => h.evidence[0]?.line)).toEqual([2]);
  });

  it("skips references, empties, placeholders, docker secret files and plain words", async () => {
    expect(await ids({
      "compose.yaml": [
        "services:",
        "  a:",
        "    environment:",
        "      - DB_PASSWORD=${DB_PASSWORD}",
        "      - API_TOKEN=$API_TOKEN",
        "      - EMPTY_SECRET=",
        "      - MY_TOKEN=your_token_here",
        "      - OTHER_PASSWORD=change_me_please",
        "      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password",
        "      - POSTGRES_PASSWORD=postgres",
        "      - NODE_ENV=production",
        "      - AUTH_TOKEN_TTL=3600",
        "    labels:",
        `      traefik.token: ${value}`,
      ].join("\n"),
      ".github/workflows/ci.yml": "env:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n  X_KEY: ${{ env.Y }}\n",
      Dockerfile: "FROM a\nARG TOKEN\nENV PASSWORD=\nENV API_KEY=${API_KEY}\n",
    })).toEqual([]);
  });

  it("does not run on other yaml or code (SEC-090 and providers cover those)", async () => {
    expect(await ids({ "config/app.yml": `api_token: ${value}\n`, "src/a.ts": `const x = { API_TOKEN: ${value} };\n` })).toEqual([]);
  });

  it("lets provider patterns win without a duplicate SEC-111", async () => {
    const token = SAMPLES["SEC-010"] as string;
    const found = await ids({ "docker-compose.yml": `services:\n  a:\n    environment:\n      - GH_TOKEN=${token}\n` });
    expect(found).toEqual(["SEC-010"]);
  });

  it("does not duplicate SEC-090 for a quoted high-entropy value", async () => {
    const found = await ids({ "docker-compose.yml": `services:\n  a:\n    environment:\n      API_TOKEN: "${value}"\n` });
    expect(found.filter((i) => i === "SEC-111" || i === "SEC-090")).toHaveLength(1);
  });
});

describe("SEC-112 Dockerfile copies the whole context without excluding .env", () => {
  const dockerfile = "FROM node:20\nWORKDIR /app\nCOPY . .\nCMD [\"node\", \"x.js\"]\n";

  it("flags COPY . . with no .dockerignore, as medium, with the line", async () => {
    const { findings } = await scan({ Dockerfile: dockerfile });
    const hit = findings.find((f) => f.ruleId === "SEC-112");
    expect(hit).toMatchObject({ severity: "medium", agentId: "secrets-hunter" });
    expect(hit?.evidence[0]).toMatchObject({ file: "Dockerfile", line: 3 });
    expect(hit?.explanation).toMatch(/\.env/);
  });

  it("covers COPY flags, ADD, ./ forms and Dockerfile.prod / *.dockerfile", async () => {
    const a = await only("SEC-112", { "Dockerfile.prod": "FROM a\nCOPY --chown=node:node . .\n" });
    const b = await only("SEC-112", { "web.dockerfile": "FROM a\nADD . /app\n" });
    const c = await only("SEC-112", { "apps/web/Dockerfile": "FROM a\nCOPY ./ ./\n" });
    expect([a.length, b.length, c.length]).toEqual([1, 1, 1]);
  });

  it("flags a .dockerignore that does not exclude .env", async () => {
    expect(await ids({ Dockerfile: dockerfile, ".dockerignore": "node_modules\n.git\n!.env\n" })).toEqual(["SEC-112"]);
  });

  it("accepts .env, .env*, .env.*, **/.env* and *.env* exclusions", async () => {
    for (const rule of [".env*", ".env.*", "**/.env*", "/.env*", "*.env*"]) {
      expect(await ids({ Dockerfile: dockerfile, ".dockerignore": `node_modules\n${rule}\n` })).toEqual([]);
    }
  });

  it("accepts a bare .env only when no other .env.* file exists", async () => {
    expect(await ids({ Dockerfile: dockerfile, ".dockerignore": ".env\n", ".env": "A=1\n", ".gitignore": ".env\n" })).toEqual([]);
    expect(await ids({
      Dockerfile: dockerfile, ".dockerignore": ".env\n", ".env.production": "A=1\n", ".gitignore": ".env.production\n",
    })).toEqual(["SEC-112"]);
  });

  it("uses a .dockerignore next to the Dockerfile, at the root, or named after the Dockerfile", async () => {
    expect(await ids({ "apps/web/Dockerfile": dockerfile, "apps/web/.dockerignore": ".env*\n" })).toEqual([]);
    expect(await ids({ "apps/web/Dockerfile": dockerfile, ".dockerignore": ".env*\n" })).toEqual([]);
    expect(await ids({ "Dockerfile.prod": dockerfile, "Dockerfile.prod.dockerignore": ".env*\n" })).toEqual([]);
  });

  it("ignores Dockerfiles that copy specific paths or other stages", async () => {
    expect(await ids({
      Dockerfile: "FROM a\nCOPY package*.json ./\nCOPY src ./src\nCOPY --from=build /app/dist ./dist\nCOPY ./public ./public\n",
    })).toEqual([]);
  });

  it("lowers confidence when the copy is in a build stage that is not the final image", async () => {
    const multi = "FROM node AS build\nCOPY . .\nRUN build\nFROM nginx\nCOPY --from=build /app/dist /usr/share/nginx\n";
    const hit = (await only("SEC-112", { Dockerfile: multi }))[0];
    expect(hit?.confidence).toBe("low");
    const single = (await only("SEC-112", { Dockerfile: dockerfile }))[0];
    expect(single?.confidence).toBe("medium");
  });

  it("is high confidence when a real .env file is in the repo", async () => {
    const hit = (await only("SEC-112", { Dockerfile: dockerfile, ".env": "A=1\n", ".gitignore": ".env\n" }))[0];
    expect(hit?.confidence).toBe("high");
  });
});
