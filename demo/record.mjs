/**
 * Records each demo scene as an asciicast v2 file from REAL whsquad output (current build).
 * Commands are "typed" at a human pace; their actual output is replayed line by line. A scene may
 * cut the output after one screenful (maxLines), like a video edit — no text is invented.
 *
 *   node demo/record.mjs <layout>     layout: reel (narrow, tall) | wide (16:9)
 * Output: demo/out/<layout>/<scene>.cast
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { wrapToWidth } from "../dist/reporters/wrap.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const app = path.join(here, "work", "app");
const cli = path.join(root, "bin", "whsquad.js");

export const LAYOUTS = {
  reel: { cols: 50, rows: 24 },
  wide: { cols: 84, rows: 20 },
};

const PROMPT = "\u001b[1;32m$\u001b[0m ";
const TYPE_MS = 0.035;
const LINE_MS = 0.03;

class Cast {
  constructor(cols, rows) {
    this.cols = cols;
    this.rows = rows;
    this.t = 0;
    this.events = [];
  }
  out(data, after = 0) {
    this.t += after;
    this.events.push([Number(this.t.toFixed(3)), "o", data]);
  }
  type(command) {
    this.out(PROMPT, 0.3);
    for (const ch of command) this.out(ch, TYPE_MS);
    this.out("\r\n", 0.35);
  }
  lines(text, maxLines = Infinity) {
    const all = text.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
    for (const line of all.slice(0, maxLines)) this.out(`${line}\r\n`, LINE_MS);
  }
  toString() {
    const header = { version: 2, width: this.cols, height: this.rows, env: { TERM: "xterm-256color" } };
    return [JSON.stringify(header), ...this.events.map((e) => JSON.stringify(e))].join("\n") + "\n";
  }
}

let ENV = { ...process.env, FORCE_COLOR: "1" };

function run(args) {
  const r = spawnSync(process.execPath, [cli, ...args], { cwd: app, env: ENV, encoding: "utf8" });
  return (r.stdout ?? "") + (r.stderr ?? "");
}

/** Fix the notes route the way a developer would in their editor (adds an auth + ownership check). */
const NOTES_FIXED = `import { supabase } from "@/lib/supabase";

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  await supabase.from("notes").delete().eq("id", params.id).eq("user_id", user.id);
  return Response.json({ ok: true });
}
`;

/** Runs `whsquad watch .`, edits a file, and returns the real output with arrival times. */
function recordWatch() {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, "watch", "."], { cwd: app, env: ENV });
    const t0 = Date.now();
    const chunks = [];
    p.stdout.on("data", (d) => chunks.push([(Date.now() - t0) / 1000, String(d)]));
    setTimeout(() => writeFileSync(path.join(app, "app/api/notes/[id]/route.ts"), NOTES_FIXED), 2500);
    setTimeout(() => {
      p.kill();
      resolve(chunks);
    }, 5500);
  });
}

async function record(layout) {
  const { cols, rows } = LAYOUTS[layout];
  // The real CLI wraps to COLUMNS at word boundaries, as it would in a terminal this wide.
  ENV = { ...ENV, COLUMNS: String(cols) };
  const outDir = path.join(here, "out", layout);
  mkdirSync(outDir, { recursive: true });
  spawnSync(process.execPath, [path.join(here, "make-app.mjs")], { stdio: "ignore" });
  const screen = rows - 2;
  const scenes = [];
  const scene = (name, build) => {
    const c = new Cast(cols, rows);
    build(c);
    scenes.push([name, c]);
  };

  scene("scan", (c) => {
    c.type("whsquad scan .");
    c.lines(run(["scan", "."]));
  });
  scene("focus", (c) => {
    c.type("whsquad scan . --only DB-001,SEC-004");
    c.lines(run(["scan", ".", "--only", "DB-001,SEC-004"]));
  });
  scene("fix", (c) => {
    c.type("whsquad fix .");
    c.lines(run(["fix", "."]), screen);
  });
  scene("prompt", (c) => {
    c.type("whsquad fix . --format prompt");
    // The prompt is printed unwrapped (it is meant to be copied); word-wrap it for display only.
    c.lines(wrapToWidth(run(["fix", ".", "--format", "prompt"]), cols), screen);
  });
  scene("verify", (c) => {
    c.type("whsquad fix . --write");
    c.lines(run(["fix", ".", "--write"]));
    c.type("whsquad verify DB-001 .");
    c.lines(run(["verify", "DB-001", "."]));
    c.out("", 1.8);
  });
  const watch = await recordWatch();
  scene("watch", (c) => {
    c.type("whsquad watch .");
    // Real arrival times, relative to when the watcher started.
    let previous = 0;
    for (const [at, data] of watch) {
      c.out(data.replace(/\r?\n/g, "\r\n"), Math.max(0.05, at - previous));
      previous = at;
    }
    c.out("", 1.5);
  });

  for (const [name, c] of scenes) {
    writeFileSync(path.join(outDir, `${name}.cast`), c.toString());
    process.stdout.write(`${layout}/${name}.cast  ${c.t.toFixed(1)} s\n`);
  }
}

const layout = process.argv[2] ?? "reel";
if (!LAYOUTS[layout]) {
  process.stderr.write(`unknown layout ${layout}; use reel or wide\n`);
  process.exit(2);
}
await record(layout);
