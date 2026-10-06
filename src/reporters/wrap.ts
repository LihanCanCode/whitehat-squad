const ANSI = /\u001b\[[0-9;]*m/g;
const MIN_WIDTH = 20;

const visible = (s: string): number => s.replace(ANSI, "").length;

/** Wraps one line at word boundaries; continuation lines keep the line's indent plus two spaces. */
function wrapLine(line: string, width: number): string[] {
  if (visible(line) <= width) return [line];
  const indent = /^ */.exec(line)?.[0] ?? "";
  const hang = `${indent}  `;
  const words = line.slice(indent.length).split(" ");
  const out: string[] = [];
  let current = indent;
  for (const word of words) {
    const prefix = current.trim() === "" ? current : `${current} `;
    if (current.trim() !== "" && visible(prefix) + visible(word) > width) {
      out.push(current);
      current = hang + word;
    } else {
      current = prefix + word;
    }
  }
  out.push(current);
  return out;
}

/**
 * Word-wraps terminal output to `width` columns so narrow terminals do not split words. Lines after
 * `stopAt` (e.g. a SQL block meant to be copied) are left untouched. No width: returned as is.
 */
export function wrapToWidth(text: string, width: number | undefined, stopAt?: string): string {
  if (width === undefined || width < MIN_WIDTH) return text;
  const lines = text.split("\n");
  const stop = stopAt === undefined ? -1 : lines.indexOf(stopAt);
  return lines
    .flatMap((line, i) => (stop >= 0 && i >= stop ? [line] : wrapLine(line, width)))
    .join("\n");
}

/** The terminal width when known: a real TTY, else a numeric COLUMNS environment variable. */
export function terminalWidth(): number | undefined {
  if (process.stdout.isTTY && process.stdout.columns) return process.stdout.columns;
  const env = Number(process.env["COLUMNS"]);
  return Number.isInteger(env) && env > 0 ? env : undefined;
}

const STATUS: ReadonlyArray<[RegExp, string]> = [
  [/^(\s*)(FIXED)\b/, "1;32"],
  [/^(\s*)(STILL PRESENT|NEW)\b/, "1;31"],
];

/** Colours verify/watch status words (FIXED green, STILL PRESENT / NEW red) when colour is on. */
export function paintStatus(text: string, color: boolean): string {
  if (!color) return text;
  return text
    .split("\n")
    .map((line) => {
      for (const [re, sgr] of STATUS) {
        if (re.test(line)) return line.replace(re, (_m, indent: string, word: string) => `${indent}\u001b[${sgr}m${word}\u001b[0m`);
      }
      return line;
    })
    .join("\n");
}
