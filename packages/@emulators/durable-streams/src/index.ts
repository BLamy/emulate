import type { AppEnv, Hono, RouteContext, ServicePlugin, Store, TokenMap, WebhookDispatcher } from "@emulators/core";
import { getDurableStreamsStore } from "./store.js";
import { seedStream } from "./helpers.js";
import { inspectorRoutes } from "./routes/inspector.js";
import { streamRoutes } from "./routes/streams.js";

export { getDurableStreamsStore, type DurableStreamsStore } from "./store.js";
export * from "./entities.js";

export interface DurableStreamsSeedConfig {
  port?: number;
  baseUrl?: string;
  streams?: Array<{
    path: string;
    content_type?: string;
    body?: string;
    closed?: boolean;
  }>;
}

function normalizeSeedPath(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
}

function seedDefaults(store: Store): void {
  const ds = getDurableStreamsStore(store);
  seedStream(ds, "/streams/emulate-default", "application/json", "[]");
}

export function seedFromConfig(store: Store, _baseUrl: string, config: DurableStreamsSeedConfig): void {
  const ds = getDurableStreamsStore(store);
  for (const stream of config.streams ?? []) {
    seedStream(
      ds,
      normalizeSeedPath(stream.path),
      stream.content_type ?? "application/octet-stream",
      stream.body,
      stream.closed ?? false,
    );
  }
}

export const durableStreamsPlugin: ServicePlugin = {
  name: "durable-streams",
  register(app: Hono<AppEnv>, store: Store, webhooks: WebhookDispatcher, baseUrl: string, tokenMap?: TokenMap): void {
    const ctx: RouteContext = { app, store, webhooks, baseUrl, tokenMap };
    inspectorRoutes(ctx);
    streamRoutes(ctx);
  },
  seed(store: Store): void {
    seedDefaults(store);
  },
};

export default durableStreamsPlugin;
