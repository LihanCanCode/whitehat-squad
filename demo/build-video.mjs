/**
 * Builds the demo videos from real recordings:
 *   1. records every scene (demo/record.mjs) from the current whsquad build
 *   2. renders each asciicast with agg (demo/tools/agg.exe) and converts it to mp4
 *   3. voices each narration line with edge-tts (demo/tools/py)
 *   4. lays out title/terminal/end segments, timed to the voice, with burned-in captions
 *
 *   node demo/build-video.mjs [reel|wide|gif|all]
 * Output: demo/out/reel.mp4 (1080x1920), demo/out/demo.mp4 (1920x1080), docs/demo.gif
 * Everything (tools, temp files, renders) stays inside the project folder.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const out = path.join(here, "out");
const tmp = path.join(here, "work", "tmp");
mkdirSync(tmp, { recursive: true });
const ENV = { ...process.env, TMP: tmp, TEMP: tmp, PYTHONPATH: path.join(here, "tools", "py") };
const AGG = path.join(here, "tools", process.platform === "win32" ? "agg.exe" : "agg");
const NARRATION = JSON.parse(readFileSync(path.join(here, "narration.json"), "utf8"));

const BG = "0d1117";
const FPS = 30;
const LEAD = 0.25; // silence before each line
const TAIL = 0.45; // breathing room after each line

const LAYOUT = {
  reel: { w: 1080, h: 1920, font: 34, termW: 1000, termY: 200, title: 76, sub: 40, capSize: 58, capMargin: 170 },
  wide: { w: 1920, h: 1080, font: 30, termW: 1500, termY: 30, title: 84, sub: 42, capSize: 46, capMargin: 40 },
};

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { env: ENV, encoding: "utf8", ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")}\n${r.stderr || r.stdout}`);
  return r.stdout;
}
const ffmpeg = (args, cwd = out) => sh("ffmpeg", ["-v", "error", "-y", ...args], { cwd });
const duration = (file) =>
  Number(sh("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", file]).trim());

/** One mp3 per narration line, cached by text. */
function voice() {
  const dir = path.join(out, "voice");
  mkdirSync(dir, { recursive: true });
  return NARRATION.beats.map((b) => {
    const file = path.join(dir, `${b.id}.mp3`);
    const stamp = `${file}.txt`;
    const key = `${NARRATION.voice}|${NARRATION.rate}|${b.text}`;
    if (!existsSync(file) || !existsSync(stamp) || readFileSync(stamp, "utf8") !== key) {
      sh("python", ["-m", "edge_tts", "--voice", NARRATION.voice, `--rate=${NARRATION.rate}`, "--text", b.text, "--write-media", file]);
      writeFileSync(stamp, key);
    }
    return { ...b, file, seconds: duration(file) };
  });
}

/** agg render of one scene → mp4 at the layout's terminal width. */
function renderScene(layout, scene) {
  const dir = path.join(out, layout);
  const gif = path.join(dir, `${scene}.gif`);
  sh(AGG, ["-q", "--theme", "github-dark", "--font-size", String(LAYOUT[layout].font), "--text-font-family", "Cascadia Mono,Consolas",
    "--last-frame-duration", "0.1", "--idle-time-limit", "3", "--no-loop", path.join(dir, `${scene}.cast`), gif]);
  const mp4 = path.join(dir, `${scene}.mp4`);
  ffmpeg(["-i", gif, "-vf", `fps=${FPS},format=yuv420p,scale=trunc(iw/2)*2:trunc(ih/2)*2`, "-c:v", "libx264", "-crf", "18", mp4]);
  return mp4;
}

const esc = (s) => s.replace(/\\/g, "\\\\").replace(/:/g, "\\:").replace(/'/g, "\u2019").replace(/%/g, "\\%");

/** Title / end card: brand text on the background, held for `seconds`. */
function card(layout, name, lines, seconds) {
  const L = LAYOUT[layout];
  const file = path.join(out, layout, `${name}.mp4`);
  // lines: [text, "title" | "sub", colour]
  const text = lines
    .map(([l, kind, color], i) => {
      const size = kind === "title" ? L.title : L.sub;
      const y = `(h/2)-${(lines.length - 1) * 60}+${i * 130}-th/2`;
      return `drawtext=font='Segoe UI Semibold':fontsize=${size}:fontcolor=${color}:x=(w-tw)/2:y=${y}:text='${esc(l)}'`;
    })
    .join(",");
  ffmpeg(["-f", "lavfi", "-i", `color=c=0x${BG}:s=${L.w}x${L.h}:r=${FPS}:d=${seconds.toFixed(3)}`, "-vf", `${text},format=yuv420p`,
    "-c:v", "libx264", "-crf", "18", file]);
  return file;
}

/** Terminal clip placed on the layout canvas with a small brand header, held/padded to `seconds`. */
function terminalSegment(layout, clip, seconds, name) {
  const L = LAYOUT[layout];
  const file = path.join(out, layout, `seg-${name}.mp4`);
  const pad = Math.max(0, seconds - duration(clip));
  const header = layout === "reel"
    ? `,drawtext=font='Segoe UI':fontsize=46:fontcolor=white:x=(w-tw)/2:y=110:text='whitehat-squad'`
    : "";
  ffmpeg(["-i", clip, "-f", "lavfi", "-i", `color=c=0x${BG}:s=${L.w}x${L.h}:r=${FPS}`,
    "-filter_complex",
    `[0:v]tpad=stop_mode=clone:stop_duration=${pad.toFixed(3)},scale=${L.termW}:-2[t];` +
      `[1:v][t]overlay=x=(W-w)/2:y=${L.termY}:shortest=1${header},format=yuv420p[v]`,
    "-map", "[v]", "-t", seconds.toFixed(3), "-c:v", "libx264", "-crf", "18", "-r", String(FPS), file]);
  return file;
}

const assTime = (t) => {
  const cs = Math.round(t * 100);
  const p = (n) => String(n).padStart(2, "0");
  return `${Math.floor(cs / 360000)}:${p(Math.floor(cs / 6000) % 60)}:${p(Math.floor(cs / 100) % 60)}.${p(cs % 100)}`;
};

/** ASS captions with PlayRes = the video size, so font size and margins are real pixels. */
function assFile(L, events) {
  return [
    "[Script Info]", "ScriptType: v4.00+", `PlayResX: ${L.w}`, `PlayResY: ${L.h}`, "WrapStyle: 0", "",
    "[V4+ Styles]",
    "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
    `Style: Cap,Segoe UI,${L.capSize},&H00FFFFFF,&H00FFFFFF,&H00000000,&H99000000,-1,0,0,0,100,100,0,0,1,3,0,2,70,70,${L.capMargin},1`,
    "", "[Events]", "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
    ...events.map(([a, b, text]) => `Dialogue: 0,${assTime(a)},${assTime(b)},Cap,,0,0,0,,${text}`),
    "",
  ].join("\n");
}

function build(layout) {
  mkdirSync(path.join(out, layout), { recursive: true });
  execFileSync(process.execPath, [path.join(here, "record.mjs"), layout], { env: ENV, stdio: "inherit" });
  const lines = voice();
  const segments = [];
  const caps = [];
  const audio = [];
  let t = 0;
  for (const [i, b] of lines.entries()) {
    const speech = LEAD + b.seconds + TAIL;
    let file;
    if (b.scene) {
      const clip = renderScene(layout, b.scene);
      file = terminalSegment(layout, clip, Math.max(speech, duration(clip) + 0.6), b.id);
    } else if (b.id === "title") {
      file = card(layout, b.id, [["Your vibe-coded app", "title", "white"], ["is leaking.", "title", "0xff7b72"]], speech);
    } else {
      file = card(layout, b.id, [
        ["whitehat-squad", "title", "white"],
        ["find  \u2192  fix  \u2192  verify", "sub", "0x7ee787"],
        ["github.com/LihanCanCode/whitehat-squad", "sub", "0x8b949e"],
      ], speech + 1);
    }
    const seg = duration(file);
    segments.push(file);
    caps.push([t + LEAD, t + LEAD + b.seconds, b.text]);
    // Voice line padded with silence to the segment length.
    const a = path.join(out, layout, `a-${b.id}.wav`);
    ffmpeg(["-i", b.file, "-af", `adelay=${Math.round(LEAD * 1000)}:all=1,apad,atrim=0:${seg.toFixed(3)}`, "-ar", "48000", "-ac", "2", a]);
    audio.push(a);
    t += seg;
  }
  const listV = path.join(out, layout, "video.txt");
  const listA = path.join(out, layout, "audio.txt");
  writeFileSync(listV, segments.map((f) => `file '${f.replace(/\\/g, "/")}'`).join("\n"));
  writeFileSync(listA, audio.map((f) => `file '${f.replace(/\\/g, "/")}'`).join("\n"));
  const L = LAYOUT[layout];
  writeFileSync(path.join(out, layout, "captions.ass"), assFile(L, caps));
  const name = layout === "reel" ? "reel.mp4" : "demo.mp4";
  // cwd = demo/out/<layout> so the subtitles filter gets a plain relative path (no Windows drive colon).
  ffmpeg(["-f", "concat", "-safe", "0", "-i", "video.txt", "-f", "concat", "-safe", "0", "-i", "audio.txt",
    "-vf", "subtitles=captions.ass", "-c:v", "libx264", "-crf", "20", "-preset", "medium",
    "-c:a", "aac", "-b:a", "160k", "-af", "loudnorm=I=-16:TP=-1.5:LRA=11", "-movflags", "+faststart", "-shortest", path.join(out, name)],
  path.join(out, layout));
  process.stdout.write(`${name}: ${duration(path.join(out, name)).toFixed(1)} s\n`);
}

/** README hero GIF: the wide scan + verify scenes, no audio, small palette. */
function gif() {
  const dir = path.join(out, "wide");
  const parts = ["scan", "verify"].map((s) => path.join(dir, `${s}.mp4`));
  for (const p of parts) if (!existsSync(p)) throw new Error(`render the wide layout first (${p} missing)`);
  writeFileSync(path.join(dir, "gif.txt"), parts.map((f) => `file '${f.replace(/\\/g, "/")}'`).join("\n"));
  const target = path.join(root, "docs", "demo.gif");
  ffmpeg(["-f", "concat", "-safe", "0", "-i", "gif.txt", "-vf",
    "fps=8,scale=860:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle",
    target], dir);
  process.stdout.write(`docs/demo.gif: ${(readFileSync(target).length / 1e6).toFixed(2)} MB\n`);
}

const what = process.argv[2] ?? "all";
if (what === "reel" || what === "all") build("reel");
if (what === "wide" || what === "all") build("wide");
if (what === "gif" || what === "all") gif();
