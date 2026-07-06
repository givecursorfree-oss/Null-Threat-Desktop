/**
 * Release builds remap developer/build-machine paths so panic metadata never
 * embeds usernames or local checkout paths in shipped binaries.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** When APPLE_SIGNING_IDENTITY is set, override ad-hoc "-" in tauri.conf for release signing. */
function applyMacSigningIdentity() {
  const identity = process.env.APPLE_SIGNING_IDENTITY?.trim();
  if (!identity) {
    return;
  }

  const confPath = path.join(projectRoot, "src-tauri", "tauri.conf.json");
  const conf = JSON.parse(fs.readFileSync(confPath, "utf8"));
  conf.bundle ??= {};
  conf.bundle.macOS ??= {};
  conf.bundle.macOS.signingIdentity = identity;
  fs.writeFileSync(confPath, `${JSON.stringify(conf, null, 2)}\n`);
}

function remapFlag(from) {
  return `--remap-path-prefix=${path.resolve(from)}=.`;
}

const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

function buildRemapFlags() {
  const flags = [];

  if (process.env.GITHUB_ACTIONS) {
    // CI: remap the runner home + workflow checkout only. Never remap all of /Users/.
    if (process.env.RUSTFLAGS) {
      flags.push(process.env.RUSTFLAGS);
    }
    flags.push(remapFlag(os.homedir()));
    return flags;
  }

  flags.push(remapFlag(os.homedir()));
  flags.push(remapFlag(projectRoot));
  flags.push("--remap-path-prefix=/home/runner/work=.");
  return flags;
}

const rustflags = buildRemapFlags().filter(Boolean);
const encodedRustflags = rustflags.join("\x1f");

applyMacSigningIdentity();

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
