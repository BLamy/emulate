import { createHash } from "node:crypto";
import { createWriteStream, existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, readFile, rename, rm } from "node:fs/promises";
import { get } from "node:https";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface NativeTarget {
  platform: NodeJS.Platform;
  arch: NodeJS.Architecture;
}

export interface NativeBinaryManifest {
  version: string;
  binaries: Record<string, { asset: string; sha256: string }>;
}

export interface NativeResolveOptions {
  target?: NativeTarget;
  env?: NodeJS.ProcessEnv;
  exists?: (path: string) => boolean;
  cacheDir?: string;
  packageVersion?: string;
  manifest?: NativeBinaryManifest;
  repository?: string;
  download?: (url: string, destination: string) => Promise<void>;
  log?: (message: string) => void;
}

export type NativeResolveResult =
  | { ok: true; path: string; asset?: string }
  | { ok: false; message: string; asset?: string };

const defaultRepository = "vercel-labs/emulate";
const currentFile = fileURLToPath(import.meta.url);
const currentDir = dirname(currentFile);
const packageRoot = join(currentDir, "..");
const manifestPath = join(currentDir, "native-manifest.json");

const supportedTargets = new Set([
  "darwin:arm64",
  "darwin:x64",
  "linux:arm64",
  "linux:x64",
  "win32:arm64",
  "win32:x64",
]);

export function nativeTargetKey(target: NativeTarget = process): string | undefined {
  const key = `${target.platform}:${target.arch}`;
  if (!supportedTargets.has(key)) {
    return undefined;
  }
  return `${target.platform}-${target.arch}`;
}

export function nativeAssetName(target: NativeTarget = process): string | undefined {
  const key = nativeTargetKey(target);
  if (!key) {
    return undefined;
  }
  return target.platform === "win32" ? `emulate-${key}.exe` : `emulate-${key}`;
}

export async function resolveNativeBinary(options: NativeResolveOptions = {}): Promise<NativeResolveResult> {
  const env = options.env ?? process.env;
  const exists = options.exists ?? existsSync;
  const override = env.EMULATE_NATIVE_BINARY;
  if (override) {
    if (exists(override)) {
      return { ok: true, path: override };
    }
    return { ok: false, message: `EMULATE_NATIVE_BINARY does not exist: ${override}` };
  }

  const target = options.target ?? process;
  const targetKey = nativeTargetKey(target);
  const asset = nativeAssetName(target);
  if (!targetKey || !asset) {
    return {
      ok: false,
      message: `No native emulate binary is published for ${target.platform}/${target.arch}.`,
    };
  }

  const localBinary = localDevelopmentBinary(target);
  if (localBinary && exists(localBinary)) {
    return { ok: true, path: localBinary, asset };
  }

  const version = options.packageVersion ?? packageVersion();
  const manifest = options.manifest ?? loadNativeManifest();
  const entry = manifest?.binaries[targetKey];
  if (!manifest || manifest.version !== version || !entry || entry.asset !== asset) {
    return {
      ok: false,
      asset,
      message: [
        `Native binary checksum metadata is missing for ${target.platform}/${target.arch}.`,
        `Expected ${asset} for emulate ${version}.`,
        "Set EMULATE_NATIVE_BINARY to a locally built binary or reinstall from a release that includes native metadata.",
      ].join("\n"),
    };
  }

  const cacheDir = options.cacheDir ?? defaultCacheDir(target, env);
  if (!cacheDir) {
    return {
      ok: false,
      asset,
      message:
        "Unable to determine a native binary cache directory. Set EMULATE_NATIVE_CACHE_DIR or EMULATE_NATIVE_BINARY.",
    };
  }

  const cachePath = join(cacheDir, "native", version, targetKey, executableName(target));
  if (exists(cachePath)) {
    if (await fileMatchesSha256(cachePath, entry.sha256)) {
      await makeExecutable(cachePath, target);
      return { ok: true, path: cachePath, asset };
    }
    await rm(cachePath, { force: true });
  }

  const url = releaseAssetUrl(options.repository ?? defaultRepository, version, asset);
  const tempPath = `${cachePath}.${process.pid}.${Date.now()}.download`;
  try {
    options.log?.(`Downloading native npx emulate engine for ${target.platform}/${target.arch}.`);
    await mkdir(dirname(cachePath), { recursive: true });
    await (options.download ?? downloadFile)(url, tempPath);
    if (!(await fileMatchesSha256(tempPath, entry.sha256))) {
      throw new Error(`Checksum mismatch for ${asset}.`);
    }
    await makeExecutable(tempPath, target);
    await rm(cachePath, { force: true });
    await rename(tempPath, cachePath);
    await makeExecutable(cachePath, target);
    return { ok: true, path: cachePath, asset };
  } catch (error) {
    await rm(tempPath, { force: true });
    const detail = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      asset,
      message: [
        `Unable to download native emulate binary for ${target.platform}/${target.arch}.`,
        `Asset: ${url}`,
        `Cache: ${cachePath}`,
        `Reason: ${detail}`,
        "First run requires network access. Set EMULATE_NATIVE_BINARY to use a local binary.",
      ].join("\n"),
    };
  }
}

function localDevelopmentBinary(target: NativeTarget): string | undefined {
  if (target.platform !== process.platform || target.arch !== process.arch) {
    return undefined;
  }
  return join(currentDir, "native", executableName(target));
}

function executableName(target: NativeTarget): string {
  return target.platform === "win32" ? "emulate.exe" : "emulate";
}

function packageVersion(): string {
  const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as { version: string };
  return pkg.version;
}

function loadNativeManifest(): NativeBinaryManifest | undefined {
  try {
    return JSON.parse(readFileSync(manifestPath, "utf8")) as NativeBinaryManifest;
  } catch {
    return undefined;
  }
}

function defaultCacheDir(target: NativeTarget, env: NodeJS.ProcessEnv): string | undefined {
  if (env.EMULATE_NATIVE_CACHE_DIR) {
    return env.EMULATE_NATIVE_CACHE_DIR;
  }
  if (target.platform === "win32") {
    const base = env.LOCALAPPDATA ?? (env.USERPROFILE ? join(env.USERPROFILE, "AppData", "Local") : undefined);
    return base ? join(base, "emulate", "Cache") : undefined;
  }
  const home = env.HOME || homedir();
  if (!home) {
    return undefined;
  }
  if (target.platform === "darwin") {
    return join(home, "Library", "Caches", "emulate");
  }
  return join(env.XDG_CACHE_HOME ?? join(home, ".cache"), "emulate");
}

function releaseAssetUrl(repository: string, version: string, asset: string): string {
  return `https://github.com/${repository}/releases/download/v${version}/${asset}`;
}

async function fileMatchesSha256(path: string, expected: string): Promise<boolean> {
  const content = await readFile(path);
  const actual = createHash("sha256").update(content).digest("hex");
  return actual.toLowerCase() === expected.toLowerCase();
}

async function makeExecutable(path: string, target: NativeTarget): Promise<void> {
  if (target.platform !== "win32") {
    await chmod(path, 0o755);
  }
}

async function downloadFile(url: string, destination: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const file = createWriteStream(destination, { mode: 0o755 });
    let settled = false;

    const fail = (error: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      file.destroy();
      reject(error);
    };

    const request = (currentUrl: string, redirects: number) => {
      const req = get(currentUrl, (response) => {
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status) && response.headers.location) {
          response.resume();
          if (redirects >= 5) {
            fail(new Error("Too many redirects."));
            return;
          }
          request(new URL(response.headers.location, currentUrl).toString(), redirects + 1);
          return;
        }
        if (status !== 200) {
          response.resume();
          fail(new Error(`HTTP ${status}`));
          return;
        }
        response.pipe(file);
        file.once("finish", () => {
          file.close((error) => {
            if (error) {
              fail(error);
              return;
            }
            if (!settled) {
              settled = true;
              resolve();
            }
          });
        });
      });
      req.once("error", fail);
    };

    file.once("error", fail);
    request(url, 0);
  });
}
