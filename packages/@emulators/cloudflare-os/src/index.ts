import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type {
  AppEnv,
  Hono,
  RouteContext,
  ServicePlugin,
  ServiceRuntime,
  Store,
  TokenMap,
  WebhookDispatcher,
} from "@emulators/core";

export interface CloudflareOsRuntimeConfig {
  enabled?: boolean;
  source?: string;
  command?: string;
  args?: string[];
  host?: string;
  port?: number;
  health_path?: string;
  startup_timeout_ms?: number;
  env?: Record<string, string>;
}

export interface CloudflareOsSeedConfig {
  port?: number;
  baseUrl?: string;
  source?: string;
  runtime?: CloudflareOsRuntimeConfig;
}

interface RuntimeStatus {
  state: "disabled" | "starting" | "ready" | "failed" | "stopped";
  runtimeUrl: string;
  source: string | null;
  pid: number | null;
  error?: string;
}

const CONFIG_KEY = "cloudflare-os.config";
const STATUS_KEY = "cloudflare-os.status";
const RUNTIME_URL_KEY = "cloudflare-os.runtimeUrl";
const DEFAULT_STARTUP_TIMEOUT_MS = 120_000;

function readConfig(store: Store): CloudflareOsSeedConfig {
  return store.getData<CloudflareOsSeedConfig>(CONFIG_KEY) ?? {};
}

function runtimeConfig(config: CloudflareOsSeedConfig): CloudflareOsRuntimeConfig {
  return config.runtime ?? {};
}

function runtimeUrl(config: CloudflareOsSeedConfig, serviceUrl: string): string {
  const service = new URL(serviceUrl);
  const runtime = runtimeConfig(config);
  const host = runtime.host ?? "127.0.0.1";
  const port = runtime.port ?? Number(service.port || 80) + 1;
  return `http://${host}:${port}`;
}

function setStatus(store: Store, status: RuntimeStatus): void {
  store.setData(STATUS_KEY, status);
}

function getStatus(store: Store, serviceUrl: string): RuntimeStatus {
  return (
    store.getData<RuntimeStatus>(STATUS_KEY) ?? {
      state: "disabled",
      runtimeUrl: runtimeUrl(readConfig(store), serviceUrl),
      source: null,
      pid: null,
    }
  );
}

function resolveSource(config: CloudflareOsSeedConfig): string | null {
  const source = runtimeConfig(config).source ?? config.source;
  return typeof source === "string" && source.trim().length > 0 ? path.resolve(source) : null;
}

function assertOfficialCheckout(source: string): void {
  const packagePath = path.join(source, "package.json");
  if (!existsSync(packagePath)) {
    throw new Error(`Cloudflare OS source is not a checkout with package.json: ${source}`);
  }

  let packageJson: { name?: unknown; scripts?: Record<string, unknown> };
  try {
    packageJson = JSON.parse(readFileSync(packagePath, "utf8")) as typeof packageJson;
  } catch (error) {
    throw new Error(`Cloudflare OS package.json is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (packageJson.name !== "cloudflare-os" || typeof packageJson.scripts?.["run-local"] !== "string") {
    throw new Error("Cloudflare OS source must be the official checkout with a run-local script");
  }
}

function expandArg(value: string, port: number, host: string): string {
  return value.replaceAll("{port}", String(port)).replaceAll("{host}", host);
}

function signalChild(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid) return;
  try {
    if (process.platform !== "win32") {
      process.kill(-child.pid, signal);
      return;
    }
  } catch {
    // Fall through to the direct child signal when process groups are unavailable.
  }
  try {
    child.kill(signal);
  } catch {
    // The child may have exited between the status check and the signal.
  }
}

async function waitForRuntime(url: string, healthPath: string, timeoutMs: number, child: ChildProcess): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError = "runtime did not become ready";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Cloudflare OS runtime exited before ready with code ${child.exitCode}`);
    }
    try {
      const response = await fetch(new URL(healthPath, `${url}/`), {
        redirect: "manual",
        signal: AbortSignal.timeout(1_000),
      });
      if (response.status < 500) return;
      lastError = `runtime returned HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Cloudflare OS runtime did not become ready within ${timeoutMs}ms: ${lastError}`);
}

async function closeChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  signalChild(child, "SIGTERM");
  await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 10_000))]);
  if (child.exitCode === null && child.signalCode === null) {
    signalChild(child, "SIGKILL");
    await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 2_000))]);
  }
}

function rewriteLocation(location: string, runtime: string, publicUrl: string): string {
  try {
    const target = new URL(location, `${runtime}/`);
    const source = new URL(runtime);
    if (target.origin !== source.origin) return location;
    const rewritten = new URL(publicUrl);
    rewritten.pathname = target.pathname;
    rewritten.search = target.search;
    rewritten.hash = target.hash;
    return rewritten.toString();
  } catch {
    return location;
  }
}

async function proxyToRuntime(request: Request, runtime: string, publicUrl: string): Promise<Response> {
  const incoming = new URL(request.url);
  const target = new URL(runtime);
  target.pathname = incoming.pathname;
  target.search = incoming.search;

  const headers = new Headers(request.headers);
  headers.delete("connection");
  headers.delete("content-length");
  headers.delete("host");
  headers.delete("origin");

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = await request.arrayBuffer();
  }

  const response = await fetch(target, init);
  const responseHeaders = new Headers(response.headers);
  const location = responseHeaders.get("location");
  if (location) responseHeaders.set("location", rewriteLocation(location, runtime, publicUrl));
  responseHeaders.delete("content-length");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

function registerRoutes({ app, store, baseUrl }: RouteContext): void {
  app.get("/_emulate/health", (c) => {
    const status = getStatus(store, baseUrl);
    return c.json(
      {
        ok: status.state === "ready",
        service: "cloudflare-os",
        providerContract: "official-runtime-proxy",
        runtime: status,
      },
      status.state === "failed" ? 503 : 200,
    );
  });

  app.get("/_emulate/config", (c) => {
    const config = readConfig(store);
    const runtime = runtimeConfig(config);
    return c.json({
      service: "cloudflare-os",
      source: resolveSource(config),
      runtime: {
        enabled: runtime.enabled ?? Boolean(resolveSource(config)),
        command: runtime.command ?? "pnpm",
        args: runtime.args ?? ["run-local", "--", "--port", "{port}"],
        host: runtime.host ?? "127.0.0.1",
        port: runtime.port ?? Number(new URL(baseUrl).port || 80) + 1,
        healthPath: runtime.health_path ?? "/",
      },
    });
  });

  app.use("*", async (c, next) => {
    if (c.req.path.startsWith("/_emulate/")) {
      await next();
      return;
    }

    const status = getStatus(store, baseUrl);
    if (status.state !== "ready") {
      return c.json(
        {
          ok: false,
          error: "cloudflare_os_runtime_unavailable",
          state: status.state,
          message: "Configure cloudflare-os.runtime.source and enable the official local runtime.",
        },
        503,
      );
    }

    try {
      return await proxyToRuntime(c.req.raw, status.runtimeUrl, baseUrl);
    } catch (error) {
      return c.json(
        {
          ok: false,
          error: "cloudflare_os_runtime_request_failed",
          message: error instanceof Error ? error.message : String(error),
        },
        502,
      );
    }
  });
}

async function startRuntime(store: Store, baseUrl: string): Promise<ServiceRuntime> {
  const config = readConfig(store);
  const runtime = runtimeConfig(config);
  const source = resolveSource(config);
  const targetUrl = runtimeUrl(config, baseUrl);
  const enabled = runtime.enabled ?? Boolean(source);

  store.setData(RUNTIME_URL_KEY, targetUrl);
  if (!enabled) {
    setStatus(store, { state: "disabled", runtimeUrl: targetUrl, source, pid: null });
    return { close: () => undefined };
  }
  if (!source) {
    const error = "Cloudflare OS runtime is enabled but no official checkout source is configured";
    setStatus(store, { state: "failed", runtimeUrl: targetUrl, source: null, pid: null, error });
    throw new Error(error);
  }

  assertOfficialCheckout(source);
  const target = new URL(targetUrl);
  const port = Number(target.port);
  const host = target.hostname;
  const command = runtime.command ?? "pnpm";
  const args = (runtime.args ?? ["run-local", "--", "--port", "{port}"]).map((arg) => expandArg(arg, port, host));
  const child = spawn(command, args, {
    cwd: source,
    detached: process.platform !== "win32",
    env: { ...process.env, ...(runtime.env ?? {}), VITE_BACKEND_HOST: `${host}:${port}` },
    stdio: "inherit",
  });
  setStatus(store, { state: "starting", runtimeUrl: targetUrl, source, pid: child.pid ?? null });

  try {
    await waitForRuntime(
      targetUrl,
      runtime.health_path ?? "/",
      runtime.startup_timeout_ms ?? DEFAULT_STARTUP_TIMEOUT_MS,
      child,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setStatus(store, { state: "failed", runtimeUrl: targetUrl, source, pid: child.pid ?? null, error: message });
    await closeChild(child);
    throw error;
  }

  setStatus(store, { state: "ready", runtimeUrl: targetUrl, source, pid: child.pid ?? null });
  let closed = false;
  return {
    async close() {
      if (closed) return;
      closed = true;
      await closeChild(child);
      setStatus(store, { state: "stopped", runtimeUrl: targetUrl, source, pid: null });
    },
  };
}

export function seedFromConfig(store: Store, _baseUrl: string, config: CloudflareOsSeedConfig): void {
  store.setData(CONFIG_KEY, config);
}

export const cloudflareOsPlugin: ServicePlugin = {
  name: "cloudflare-os",
  register(app: Hono<AppEnv>, store: Store, _webhooks: WebhookDispatcher, baseUrl: string, _tokenMap?: TokenMap): void {
    registerRoutes({ app, store, webhooks: _webhooks, baseUrl, tokenMap: _tokenMap });
  },
  seed(store: Store): void {
    store.setData<CloudflareOsSeedConfig>(CONFIG_KEY, {});
  },
  start: startRuntime,
};

export default cloudflareOsPlugin;
