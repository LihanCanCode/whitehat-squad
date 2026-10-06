#!/usr/bin/env node
import("../dist/cli/main.js").then((m) => m.main(process.argv.slice(2))).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 4;
  },
);
