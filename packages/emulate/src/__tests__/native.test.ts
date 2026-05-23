import { createHash } from "node:crypto";
import { mkdir, stat, writeFile, readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { nativeAssetName, nativeTargetKey, resolveNativeBinary, type NativeBinaryManifest } from "../native.js";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("native binary resolution", () => {
  it("maps supported npm platform and arch pairs to release assets", () => {
    expect(nativeTargetKey({ platform: "darwin", arch: "arm64" })).toBe("darwin-arm64");
    expect(nativeAssetName({ platform: "darwin", arch: "arm64" })).toBe("emulate-darwin-arm64");
    expect(nativeAssetName({ platform: "darwin", arch: "x64" })).toBe("emulate-darwin-x64");
    expect(nativeAssetName({ platform: "linux", arch: "arm64" })).toBe("emulate-linux-arm64");
    expect(nativeAssetName({ platform: "linux", arch: "x64" })).toBe("emulate-linux-x64");
    expect(nativeAssetName({ platform: "win32", arch: "arm64" })).toBe("emulate-win32-arm64.exe");
    expect(nativeAssetName({ platform: "win32", arch: "x64" })).toBe("emulate-win32-x64.exe");
  });

  it("returns a clear error for unsupported targets", async () => {
    const resolved = await resolveNativeBinary({
      target: { platform: "freebsd", arch: "x64" },
      env: {},
      packageVersion: "1.2.3",
      manifest: manifest("1.2.3", "freebsd-x64", "emulate-freebsd-x64", "unused"),
    });

    expect(resolved).toEqual({
      ok: false,
      message: "No native emulate binary is published for freebsd/x64.",
    });
  });

  it("uses EMULATE_NATIVE_BINARY when it exists", async () => {
    const resolved = await resolveNativeBinary({
      env: { EMULATE_NATIVE_BINARY: "/opt/emulate" },
      exists: (path) => path === "/opt/emulate",
    });

    expect(resolved).toEqual({ ok: true, path: "/opt/emulate" });
  });

  it("returns a clear error when EMULATE_NATIVE_BINARY is missing", async () => {
    const resolved = await resolveNativeBinary({
      env: { EMULATE_NATIVE_BINARY: "/missing/emulate" },
      exists: () => false,
    });

    expect(resolved).toEqual({ ok: false, message: "EMULATE_NATIVE_BINARY does not exist: /missing/emulate" });
  });

  it("resolves a cached binary when the checksum matches", async () => {
    const root = tempRoot();
    const content = Buffer.from("native binary");
    const sha256 = digest(content);
    const binary = join(root, "native", "1.2.3", "linux-x64", "emulate");
    await mkdir(dirname(binary), { recursive: true });
    await writeFile(binary, content, { mode: 0o755, flag: "w" });

    const resolved = await resolveNativeBinary({
      target: { platform: "linux", arch: "x64" },
      env: {},
      cacheDir: root,
      packageVersion: "1.2.3",
      manifest: manifest("1.2.3", "linux-x64", "emulate-linux-x64", sha256),
      download: async () => {
        throw new Error("download should not run");
      },
    });

    expect(resolved).toEqual({ ok: true, path: binary, asset: "emulate-linux-x64" });
  });

  it("downloads, verifies, and caches a missing binary", async () => {
    const root = tempRoot();
    const content = Buffer.from("downloaded binary");
    const sha256 = digest(content);
    const messages: string[] = [];

    const resolved = await resolveNativeBinary({
      target: { platform: "linux", arch: "x64" },
      env: {},
      cacheDir: root,
      packageVersion: "1.2.3",
      repository: "acme/emulate",
      manifest: manifest("1.2.3", "linux-x64", "emulate-linux-x64", sha256),
      log: (message) => messages.push(message),
      download: async (url, destination) => {
        expect(url).toBe("https://github.com/acme/emulate/releases/download/v1.2.3/emulate-linux-x64");
        await writeFile(destination, content);
      },
    });

    const binary = join(root, "native", "1.2.3", "linux-x64", "emulate");
    expect(resolved).toEqual({ ok: true, path: binary, asset: "emulate-linux-x64" });
    await expect(readFile(binary)).resolves.toEqual(content);
    await expect(stat(binary)).resolves.toMatchObject({ mode: expect.any(Number) });
    expect(messages).toEqual(["Downloading native npx emulate engine for linux/x64."]);
  });

  it("fails when a downloaded binary does not match the checksum", async () => {
    const root = tempRoot();
    const resolved = await resolveNativeBinary({
      target: { platform: "linux", arch: "x64" },
      env: {},
      cacheDir: root,
      packageVersion: "1.2.3",
      manifest: manifest("1.2.3", "linux-x64", "emulate-linux-x64", digest(Buffer.from("expected"))),
      download: async (_url, destination) => {
        await writeFile(destination, "actual");
      },
    });

    expect(resolved.ok).toBe(false);
    if (!resolved.ok) {
      expect(resolved.asset).toBe("emulate-linux-x64");
      expect(resolved.message).toContain("Checksum mismatch for emulate-linux-x64.");
    }
  });

  it("requires release metadata for lazy downloads", async () => {
    const resolved = await resolveNativeBinary({
      target: { platform: "win32", arch: "x64" },
      env: {},
      cacheDir: tempRoot(),
      packageVersion: "1.2.3",
      manifest: manifest("1.2.3", "linux-x64", "emulate-linux-x64", "unused"),
    });

    expect(resolved.ok).toBe(false);
    if (!resolved.ok) {
      expect(resolved.asset).toBe("emulate-win32-x64.exe");
      expect(resolved.message).toContain("Native binary checksum metadata is missing for win32/x64.");
    }
  });
});

function tempRoot(): string {
  const root = `/tmp/emulate-native-test-${process.pid}-${tempRoots.length}`;
  tempRoots.push(root);
  return root;
}

function digest(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function manifest(version: string, key: string, asset: string, sha256: string): NativeBinaryManifest {
  return {
    version,
    binaries: {
      [key]: { asset, sha256 },
    },
  };
}
