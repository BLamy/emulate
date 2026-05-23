#!/usr/bin/env node

import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = JSON.parse(readFileSync(join(root, "packages/emulate/package.json"), "utf8")).version;
const assetDir = process.env.EMULATE_NATIVE_ASSET_DIR || "/tmp/emulate-native-assets";
const distDir = join(root, "packages/emulate/dist");

const allTargets = [
  { key: "darwin-arm64", asset: "emulate-darwin-arm64", goos: "darwin", goarch: "arm64" },
  { key: "darwin-x64", asset: "emulate-darwin-x64", goos: "darwin", goarch: "amd64" },
  { key: "linux-arm64", asset: "emulate-linux-arm64", goos: "linux", goarch: "arm64" },
  { key: "linux-x64", asset: "emulate-linux-x64", goos: "linux", goarch: "amd64" },
  { key: "win32-arm64", asset: "emulate-win32-arm64.exe", goos: "windows", goarch: "arm64" },
  { key: "win32-x64", asset: "emulate-win32-x64.exe", goos: "windows", goarch: "amd64" },
];

const requestedTargets = process.env.EMULATE_NATIVE_TARGETS?.split(",").map((target) => target.trim()).filter(Boolean);
const targets = requestedTargets?.length
  ? allTargets.filter((target) => requestedTargets.includes(target.key))
  : allTargets;

if (requestedTargets?.length && targets.length !== requestedTargets.length) {
  const known = new Set(allTargets.map((target) => target.key));
  const unknown = requestedTargets.filter((target) => !known.has(target));
  throw new Error(`Unknown native target: ${unknown.join(", ")}`);
}

rmSync(assetDir, { recursive: true, force: true });
mkdirSync(assetDir, { recursive: true });
mkdirSync(distDir, { recursive: true });

const manifest = { version, binaries: {} };

for (const target of targets) {
  const outFile = join(assetDir, target.asset);
  const result = spawnSync(
    "go",
    ["build", "-trimpath", "-ldflags", `-s -w -X main.version=${version}`, "-o", outFile, "./cmd/emulate"],
    {
      cwd: root,
      env: {
        ...process.env,
        CGO_ENABLED: "0",
        GOOS: target.goos,
        GOARCH: target.goarch,
      },
      stdio: "inherit",
    },
  );

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }

  if (target.goos !== "windows") {
    chmodSync(outFile, 0o755);
  }
  const sha256 = createHash("sha256").update(readFileSync(outFile)).digest("hex");
  manifest.binaries[target.key] = { asset: target.asset, sha256 };
  console.log(`Built native asset ${target.asset}`);
}

const manifestJSON = JSON.stringify(manifest, null, 2) + "\n";
writeFileSync(join(assetDir, "native-manifest.json"), manifestJSON);
writeFileSync(join(distDir, "native-manifest.json"), manifestJSON);
console.log(`Wrote native manifest for emulate ${version}`);
