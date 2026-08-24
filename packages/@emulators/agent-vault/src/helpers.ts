import { randomBytes, randomUUID } from "node:crypto";
import type { Context, ContentfulStatusCode, Store } from "@emulators/core";
import { escapeHtml } from "@emulators/core";
import { getAgentVaultStore } from "./store.js";
import type {
  AgentVaultAuth,
  AgentVaultCredential,
  AgentVaultRequestLog,
  AgentVaultRole,
  AgentVaultService,
  AgentVaultSubstitution,
  AgentVaultSubstitutionSurface,
  AgentVaultVault,
} from "./entities.js";

export const DEFAULT_VAULT_NAME = "default";
export const DEFAULT_MITM_PORT = 14322;
export const DEFAULT_CA_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBozCCAUmgAwIBAgIUA7ZlbnVsYXRlLWFnZW50LXZhdWx0MBQGCCqGSM49BAMC
MCQxIjAgBgNVBAMMGWFnZW50LXZhdWx0LmVtdWxhdGUubG9jYWwwHhcNMjYwMTAx
MDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAkMSIwIAYDVQQDDBlhZ2VudC12YXVsdC5l
bXVsYXRlLmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2HhC0VQzX62w
cORx4E0IFtZRyK5YxmhNpzWYfnkMZ5P5d13U5qR+V+fH1K+gxDrZQdl3nU3U7fYz
2n8EVqNTMFEwHQYDVR0OBBYEFGFnZW50LXZhdWx0LWVtdWxhdGUtY2EwHwYDVR0j
BBgwFoAUYWdlbnQtdmF1bHQtZW11bGF0ZS1jYTAPBgNVHRMBAf8EBTADAQH/MBQG
CCqGSM49BAMCA0gAMEUCIQCJ9R+5jQFiW0wQXQ9nR6dJ1trGzZW1cVOWXHW4Bh6m
cgIgHq5aSFlT8Wn+PxO96n00ijz0vDBXcmtjlyJ9wTfR1GU=
-----END CERTIFICATE-----
`;

const slugPattern = /^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$/;
const credentialKeyPattern = /^[A-Z][A-Z0-9_]*$/;
const headerNamePattern = /^[A-Za-z0-9-]+$/;
const supportedSurfaces = new Set<AgentVaultSubstitutionSurface>(["path", "query", "header", "body", "websocket"]);

export function generateId(prefix: string): string {
  return `${prefix}_${randomBytes(18).toString("base64url")}`;
}

export function vaultId(): string {
  return randomUUID();
}

export function jsonError(c: Context, statusCode: number, message: string, code?: string): Response {
  const body = code ? { code, error: message } : { error: message };
  return c.json(body, statusCode as ContentfulStatusCode);
}

export async function parseObjectBody(c: Context): Promise<Record<string, unknown>> {
  try {
    const body = await c.req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  } catch {
    throw new Error("Invalid request body");
  }
}

export function requireAuth(c: Context): Response | null {
  if (c.get("authToken") || c.get("authUser")) return null;
  return jsonError(c, 401, "Unauthorized");
}

export function getMitmPort(store: Store): number {
  return store.getData<number>("agent-vault.mitm_port") ?? DEFAULT_MITM_PORT;
}

export function setMitmPort(store: Store, port: number): void {
  store.setData("agent-vault.mitm_port", port);
}

export function getCaCertificate(store: Store): string {
  return store.getData<string>("agent-vault.ca_certificate") ?? DEFAULT_CA_CERTIFICATE;
}

export function setCaCertificate(store: Store, pem: string): void {
  store.setData("agent-vault.ca_certificate", pem);
}

export function validateSlug(name: string, label = "name"): string | null {
  if (!name) return `${label} is required`;
  if (!slugPattern.test(name)) {
    return `${label} must be 3-64 characters, lowercase alphanumeric and hyphens only`;
  }
  if (name.includes("--")) return `${label} must not contain consecutive hyphens`;
  return null;
}

export function validateCredentialKey(key: string): string | null {
  if (!credentialKeyPattern.test(key)) {
    return `Invalid credential key ${JSON.stringify(key)}: must be SCREAMING_SNAKE_CASE`;
  }
  return null;
}

export function validateVaultRole(role: string): role is AgentVaultRole {
  return role === "proxy" || role === "member" || role === "admin";
}

export function splitInlineHost(host: string, path = ""): { host: string; path: string; port: number | null } {
  if (path) {
    const [bareHost, port] = splitHostPort(host);
    return { host: bareHost, path, port };
  }

  const slash = host.indexOf("/");
  if (slash > 0) {
    const [bareHost, port] = splitHostPort(host.slice(0, slash));
    return { host: bareHost, path: host.slice(slash), port };
  }

  const [bareHost, port] = splitHostPort(host);
  return { host: bareHost, path: "", port };
}

function splitHostPort(host: string): [string, number | null] {
  const idx = host.lastIndexOf(":");
  if (idx < 0) return [host, null];
  const parsed = Number(host.slice(idx + 1));
  if (!Number.isInteger(parsed)) return [host, null];
  return [host.slice(0, idx), parsed];
}

export function matcherPattern(service: Pick<AgentVaultService, "host" | "path" | "port">): string {
  const host = service.port ? `${service.host}:${service.port}` : service.host;
  return service.path ? `${host}${service.path}` : host;
}

export function normalizeService(
  input: Record<string, unknown>,
  vaultIdValue: string,
): Omit<AgentVaultService, "id" | "created_at" | "updated_at"> {
  const rawHost = String(input.host ?? "");
  const rawPath = typeof input.path === "string" ? input.path : "";
  const split = splitInlineHost(rawHost, rawPath);
  const rawPort = typeof input.port === "number" && Number.isInteger(input.port) ? input.port : split.port;

  return {
    vault_id: vaultIdValue,
    name: String(input.name ?? ""),
    host: split.host,
    path: split.path,
    port: rawPort ?? null,
    enabled: typeof input.enabled === "boolean" ? input.enabled : null,
    auth: normalizeAuth(input.auth),
    substitutions: Array.isArray(input.substitutions) ? input.substitutions.map(normalizeSubstitution) : [],
  };
}

function normalizeAuth(value: unknown): AgentVaultAuth {
  const raw = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const headers =
    raw.headers && typeof raw.headers === "object" && !Array.isArray(raw.headers)
      ? Object.fromEntries(Object.entries(raw.headers).map(([key, val]) => [key, String(val)]))
      : undefined;

  return {
    type: String(raw.type ?? "") as AgentVaultAuth["type"],
    token: raw.token === undefined ? undefined : String(raw.token),
    username: raw.username === undefined ? undefined : String(raw.username),
    password: raw.password === undefined ? undefined : String(raw.password),
    key: raw.key === undefined ? undefined : String(raw.key),
    header: raw.header === undefined ? undefined : String(raw.header),
    prefix: raw.prefix === undefined ? undefined : String(raw.prefix),
    headers,
  };
}

function normalizeSubstitution(value: unknown): AgentVaultSubstitution {
  const raw = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  return {
    key: String(raw.key ?? ""),
    placeholder: String(raw.placeholder ?? ""),
    in: Array.isArray(raw.in) ? raw.in.map((surface) => String(surface) as AgentVaultSubstitutionSurface) : undefined,
  };
}

export function validateService(service: Omit<AgentVaultService, "id" | "created_at" | "updated_at">): string | null {
  const nameError = validateSlug(service.name, "service name");
  if (nameError) return nameError;
  if (!service.host) return "host is required";
  if (
    service.host.includes("/") ||
    service.host.includes("@") ||
    service.host.includes("?") ||
    service.host.includes("#")
  ) {
    return `host ${JSON.stringify(service.host)} is invalid`;
  }
  if (service.port !== null && (service.port < 1 || service.port > 65535)) {
    return `port ${service.port} is out of range`;
  }
  if (service.path && !service.path.startsWith("/")) return `path ${JSON.stringify(service.path)} must start with /`;
  return validateAuth(service.auth) ?? validateSubstitutions(service.substitutions);
}

function validateAuth(auth: AgentVaultAuth): string | null {
  switch (auth.type) {
    case "bearer":
      return auth.token ? validateCredentialKey(auth.token) : "auth: token is required for bearer auth";
    case "basic":
      if (!auth.username) return "auth: username is required for basic auth";
      return validateCredentialKey(auth.username) ?? (auth.password ? validateCredentialKey(auth.password) : null);
    case "api-key":
      if (!auth.key) return "auth: key is required for api-key auth";
      if (auth.header && !headerNamePattern.test(auth.header))
        return `auth: invalid header name ${JSON.stringify(auth.header)}`;
      return validateCredentialKey(auth.key);
    case "custom":
      if (!auth.headers || Object.keys(auth.headers).length === 0) return "auth: headers is required for custom auth";
      for (const [name, value] of Object.entries(auth.headers)) {
        if (!headerNamePattern.test(name)) return `auth: invalid header name ${JSON.stringify(name)}`;
        for (const key of credentialKeysFromTemplate(value)) {
          const err = validateCredentialKey(key);
          if (err) return err;
        }
      }
      return null;
    case "passthrough":
      return null;
    default:
      return `auth: unsupported type ${JSON.stringify(auth.type)}`;
  }
}

function validateSubstitutions(substitutions: AgentVaultSubstitution[]): string | null {
  const seen = new Set<string>();
  for (const [index, sub] of substitutions.entries()) {
    const keyError = validateCredentialKey(sub.key);
    if (keyError) return `substitution ${index}: ${keyError}`;
    if (!sub.placeholder || sub.placeholder.length > 128) return `substitution ${index}: placeholder is required`;
    if (seen.has(sub.placeholder)) return `substitution ${index}: duplicate placeholder`;
    seen.add(sub.placeholder);
    for (const surface of sub.in ?? []) {
      if (!supportedSurfaces.has(surface)) return `substitution ${index}: unsupported surface ${surface}`;
    }
  }
  return null;
}

export function credentialKeysForService(service: Pick<AgentVaultService, "auth" | "substitutions">): string[] {
  const keys: string[] = [];
  const push = (value?: string) => {
    if (value && !keys.includes(value)) keys.push(value);
  };

  switch (service.auth.type) {
    case "bearer":
      push(service.auth.token);
      break;
    case "basic":
      push(service.auth.username);
      push(service.auth.password);
      break;
    case "api-key":
      push(service.auth.key);
      break;
    case "custom":
      for (const template of Object.values(service.auth.headers ?? {})) {
        for (const key of credentialKeysFromTemplate(template)) push(key);
      }
      break;
  }

  for (const sub of service.substitutions) push(sub.key);
  return keys;
}

function credentialKeysFromTemplate(template: string): string[] {
  return [...template.matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((match) => match[1]!);
}

export function formatService(service: AgentVaultService) {
  return {
    name: service.name,
    host: matcherPattern(service),
    enabled: service.enabled ?? undefined,
    auth: service.auth,
    substitutions: service.substitutions.length > 0 ? service.substitutions : undefined,
  };
}

export function formatVault(vault: AgentVaultVault) {
  return {
    id: vault.vault_id,
    name: vault.name,
    created_at: vault.created_at,
    credential_store: vault.credential_store ?? undefined,
  };
}

export function formatCredential(credential: AgentVaultCredential, reveal: boolean) {
  return {
    key: credential.key,
    type: credential.type,
    ...(reveal ? { value: credential.value } : {}),
  };
}

export function resolveVaultName(c: Context, body?: Record<string, unknown>): string {
  const fromBody = typeof body?.vault === "string" ? body.vault : "";
  if (fromBody) return fromBody;
  const fromQuery = c.req.query("vault");
  if (fromQuery) return fromQuery;
  const fromHeader = c.req.header("x-vault");
  if (fromHeader) return fromHeader;
  const token = c.get("authToken");
  if (token) {
    const session = getAgentVaultStoreFromContext(c).sessions.findOneBy("token", token);
    if (session) return session.vault_name;
  }
  return DEFAULT_VAULT_NAME;
}

function getAgentVaultStoreFromContext(c: Context) {
  const store = c.get("agentVaultStore") as ReturnType<typeof getAgentVaultStore> | undefined;
  if (!store) throw new Error("Agent Vault store is not registered on the request context");
  return store;
}

export function vaultByName(store: Store, name: string): AgentVaultVault | undefined {
  return getAgentVaultStore(store).vaults.findOneBy("name", name);
}

export function resolveServiceRef(
  services: AgentVaultService[],
  ref: string,
): { service?: AgentVaultService; candidates?: AgentVaultService[] } {
  const byName = services.find((service) => service.name === ref);
  if (byName) return { service: byName };
  const matches = services.filter((service) => service.host === ref || matcherPattern(service) === ref);
  if (matches.length === 1) return { service: matches[0] };
  if (matches.length > 1) return { candidates: matches };
  return {};
}

export function logRequest(
  store: Store,
  log: Omit<AgentVaultRequestLog, "id" | "created_at" | "updated_at" | "log_id">,
): void {
  const avs = getAgentVaultStore(store);
  const nextId = avs.requestLogs.all().reduce((max, row) => Math.max(max, row.log_id), 0) + 1;
  avs.requestLogs.insert({ log_id: nextId, ...log });
}

export function truncate(value: string, max = 96): string {
  return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

export function htmlCell(value: string | number | null | undefined): string {
  return escapeHtml(value == null ? "" : String(value));
}
