/**
 * Release builds remap developer/build-machine paths so panic metadata never
 * embeds usernames or local checkout paths in shipped binaries.
 */
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function remapFlag(from) {
  return `--remap-path-prefix=${path.resolve(from)}=.`;
}

const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

const rustflags = [
  remapFlag(os.homedir()),
  remapFlag(projectRoot),
  "--remap-path-prefix=/home/runner/work=.",
  "--remap-path-prefix=/Users/=.",
  process.env.RUSTFLAGS,
].filter(Boolean);

// CARGO_ENCODED_RUSTFLAGS avoids Windows shell splitting on spaces in paths.
const encodedRustflags = rustflags.join("\x1f");

const { RUSTFLAGS: _drop, ...baseEnv } = process.env;

const result = spawnSync("npx", ["tauri", "build"], {
  stdio: "inherit",
  shell: true,
  env: {
    ...baseEnv,
    CARGO_ENCODED_RUSTFLAGS: encodedRustflags,
  },
});

process.exit(result.status ?? 1);
