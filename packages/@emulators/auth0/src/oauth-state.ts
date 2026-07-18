import { createHash, randomBytes } from "node:crypto";
import type { Store } from "@emulators/core";

export interface Auth0RuntimeConfig {
  now?: number;
  seed?: string;
  authorization_code_ttl_seconds?: number;
  device_code_ttl_seconds?: number;
}

export interface AuthorizationCodeGrant {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  userId: string;
  scope: string;
  audience: string;
  nonce?: string;
  expiresAt: number;
}

export interface DeviceCodeGrant {
  clientId: string;
  userCode: string;
  scope: string;
  audience: string;
  expiresAt: number;
  status: "pending" | "approved" | "denied";
  userId?: string;
}

const CONFIG_KEY = "auth0.oauth.runtime";

export function configureAuth0Runtime(store: Store, config: Auth0RuntimeConfig): void {
  const globalNow = store.getData<number>("emulate.now");
  const globalSeed = store.getData<string>("emulate.seed");
  store.setData(CONFIG_KEY, {
    ...config,
    now: config.now ?? globalNow,
    seed: config.seed ?? globalSeed,
  });
}

export function auth0Now(store: Store): number {
  return store.getData<Auth0RuntimeConfig>(CONFIG_KEY)?.now ?? Math.floor(Date.now() / 1000);
}

export function auth0Lifetime(store: Store, kind: "authorization" | "device"): number {
  const config = store.getData<Auth0RuntimeConfig>(CONFIG_KEY);
  return kind === "authorization"
    ? (config?.authorization_code_ttl_seconds ?? 300)
    : (config?.device_code_ttl_seconds ?? 600);
}

export function generateAuth0Material(store: Store, prefix: string, bytes = 24): string {
  const config = store.getData<Auth0RuntimeConfig>(CONFIG_KEY);
  if (!config?.seed) return `${prefix}_${randomBytes(bytes).toString("base64url")}`;

  const counter = store.getData<number>("auth0.oauth.materialCounter") ?? 0;
  store.setData("auth0.oauth.materialCounter", counter + 1);
  const digest = createHash("sha256").update(`${config.seed}:${counter}:${prefix}`).digest("base64url");
  return `${prefix}_${digest.slice(0, Math.ceil((bytes * 4) / 3))}`;
}

export function getAuthorizationCodes(store: Store): Map<string, AuthorizationCodeGrant> {
  let grants = store.getData<Map<string, AuthorizationCodeGrant>>("auth0.oauth.authorizationCodes");
  if (!grants) {
    grants = new Map();
    store.setData("auth0.oauth.authorizationCodes", grants);
  }
  return grants;
}

export function getDeviceCodes(store: Store): Map<string, DeviceCodeGrant> {
  let grants = store.getData<Map<string, DeviceCodeGrant>>("auth0.oauth.deviceCodes");
  if (!grants) {
    grants = new Map();
    store.setData("auth0.oauth.deviceCodes", grants);
  }
  return grants;
}
