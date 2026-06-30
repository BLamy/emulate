import { Hono } from "@emulators/core";
import {
  Store,
  WebhookDispatcher,
  authMiddleware,
  createApiErrorHandler,
  createErrorHandler,
  type AppEnv,
  type TokenMap,
} from "@emulators/core";
import { durableStreamsPlugin } from "../index.js";

export const testBaseUrl = "http://localhost:4000";
export const testToken = "test-durable-streams-token";

export function createTestApp(baseUrl: string = testBaseUrl) {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();
  tokenMap.set(testToken, {
    login: "admin",
    id: 1,
    scopes: ["streams:*"],
  });

  const app = new Hono<AppEnv>();
  app.onError(createApiErrorHandler());
  app.use("*", createErrorHandler());
  app.use("*", authMiddleware(tokenMap));
  durableStreamsPlugin.register(app, store, webhooks, baseUrl, tokenMap);
  durableStreamsPlugin.seed!(store, baseUrl);

  return { app, store, webhooks, tokenMap };
}

export function authHeaders(contentType?: string): Record<string, string> {
  return {
    Authorization: `Bearer ${testToken}`,
    ...(contentType ? { "Content-Type": contentType } : {}),
  };
}
