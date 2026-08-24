import type { Hono } from "@emulators/core";
import type { AppEnv, RouteContext, ServicePlugin, Store, TokenMap, WebhookDispatcher } from "@emulators/core";
import { getAgentVaultStore } from "./store.js";
import {
  DEFAULT_CA_CERTIFICATE,
  DEFAULT_MITM_PORT,
  DEFAULT_VAULT_NAME,
  generateId,
  normalizeService,
  setCaCertificate,
  setMitmPort,
  validateService,
  vaultId,
} from "./helpers.js";
import { vaultRoutes } from "./routes/vaults.js";
import { credentialRoutes } from "./routes/credentials.js";
import { serviceRoutes } from "./routes/services.js";
import { sessionRoutes } from "./routes/sessions.js";
import { agentRoutes } from "./routes/agents.js";
import { logRoutes } from "./routes/logs.js";
import { inspectorRoutes } from "./routes/inspector.js";
import { managementRoutes, seedManagementDefaults } from "./routes/management.js";
import type { AgentVaultCredentialStoreSummary, AgentVaultInstanceRole, AgentVaultRole } from "./entities.js";

export { getAgentVaultStore, type AgentVaultStore } from "./store.js";
export * from "./entities.js";

export interface AgentVaultSeedConfig {
  port?: number;
  baseUrl?: string;
  mitm_port?: number;
  ca_certificate?: string;
  vaults?: Array<{
    name: string;
    unmatched_host_policy?: "passthrough" | "deny";
    credential_store?: AgentVaultCredentialStoreSummary;
    credentials?: Record<string, string>;
    services?: Array<Record<string, unknown>>;
  }>;
  agents?: Array<{
    name: string;
    token?: string;
    role?: AgentVaultInstanceRole;
    vaults?: Array<{
      vault_name: string;
      vault_role?: AgentVaultRole;
    }>;
  }>;
  logs?: Array<{
    vault?: string;
    method?: string;
    host: string;
    path?: string;
    matched_service?: string;
    status?: number;
    latency_ms?: number;
    error_code?: string;
  }>;
}

export function seedFromConfig(store: Store, _baseUrl: string, config: AgentVaultSeedConfig): void {
  if (typeof config.mitm_port === "number") {
    setMitmPort(store, config.mitm_port);
  }
  if (typeof config.ca_certificate === "string" && config.ca_certificate.trim()) {
    setCaCertificate(store, config.ca_certificate);
  }

  for (const vault of config.vaults ?? []) {
    upsertVault(store, {
      name: vault.name,
      unmatchedHostPolicy: vault.unmatched_host_policy,
      credentialStore: vault.credential_store ?? null,
      credentials: vault.credentials,
      services: vault.services,
    });
  }

  for (const agent of config.agents ?? []) {
    upsertAgent(store, {
      name: agent.name,
      token: agent.token,
      role: agent.role,
      vaults:
        agent.vaults?.map((grant) => ({
          vault_name: grant.vault_name,
          vault_role: grant.vault_role ?? "proxy",
        })) ?? [],
    });
  }

  for (const log of config.logs ?? []) {
    const avs = getAgentVaultStore(store);
    const vault = avs.vaults.findOneBy("name", log.vault ?? DEFAULT_VAULT_NAME);
    if (!vault) continue;
    avs.requestLogs.insert({
      log_id: avs.requestLogs.all().reduce((max, row) => Math.max(max, row.log_id), 0) + 1,
      vault_id: vault.vault_id,
      ingress: "emulated",
      method: log.method ?? "GET",
      host: log.host,
      path: log.path ?? "/",
      matched_service: log.matched_service ?? "",
      credential_keys: [],
      status: log.status ?? 200,
      latency_ms: log.latency_ms ?? 0,
      error_code: log.error_code ?? "",
      actor_type: "user",
      actor_id: "seed",
      actor_name: "seed",
    });
  }
}

export const agentVaultPlugin: ServicePlugin = {
  name: "agent-vault",
  register(app: Hono<AppEnv>, store: Store, webhooks: WebhookDispatcher, baseUrl: string, tokenMap?: TokenMap): void {
    app.use("*", async (c, next) => {
      c.set("agentVaultStore" as never, getAgentVaultStore(store) as never);
      await next();
    });

    const ctx: RouteContext = { app, store, webhooks, baseUrl, tokenMap };
    vaultRoutes(ctx);
    credentialRoutes(ctx);
    serviceRoutes(ctx);
    sessionRoutes(ctx);
    agentRoutes(ctx);
    logRoutes(ctx);
    managementRoutes(ctx);
    inspectorRoutes(ctx);
  },
  seed(store: Store): void {
    seedDefaults(store);
  },
};

export default agentVaultPlugin;

function seedDefaults(store: Store): void {
  setMitmPort(store, DEFAULT_MITM_PORT);
  setCaCertificate(store, DEFAULT_CA_CERTIFICATE);
  upsertVault(store, {
    name: DEFAULT_VAULT_NAME,
    credentials: {
      ANTHROPIC_API_KEY: "sk-ant-emulated",
      GITHUB_PAT: "ghp_emulated",
    },
    services: [
      {
        name: "anthropic",
        host: "api.anthropic.com",
        auth: { type: "api-key", key: "ANTHROPIC_API_KEY", header: "x-api-key" },
      },
      {
        name: "github",
        host: "api.github.com",
        auth: { type: "bearer", token: "GITHUB_PAT" },
      },
    ],
  });
  upsertAgent(store, {
    name: "default-agent",
    token: "av_agt_default",
    role: "member",
    vaults: [{ vault_name: DEFAULT_VAULT_NAME, vault_role: "admin" }],
  });
  seedManagementDefaults(store);
}

function upsertVault(
  store: Store,
  input: {
    name: string;
    unmatchedHostPolicy?: "passthrough" | "deny";
    credentialStore?: AgentVaultCredentialStoreSummary | null;
    credentials?: Record<string, string>;
    services?: Array<Record<string, unknown>>;
  },
): void {
  const avs = getAgentVaultStore(store);
  let vault = avs.vaults.findOneBy("name", input.name);
  if (!vault) {
    vault = avs.vaults.insert({
      vault_id: vaultId(),
      name: input.name,
      unmatched_host_policy: input.unmatchedHostPolicy ?? "passthrough",
      credential_store: input.credentialStore ?? null,
    });
  } else {
    vault = avs.vaults.update(vault.id, {
      unmatched_host_policy: input.unmatchedHostPolicy ?? vault.unmatched_host_policy,
      credential_store: input.credentialStore ?? vault.credential_store,
    })!;
  }

  for (const [key, value] of Object.entries(input.credentials ?? {})) {
    const existing = avs.credentials.findBy("vault_id", vault.vault_id).find((credential) => credential.key === key);
    if (existing) {
      avs.credentials.update(existing.id, { value, type: "static" });
    } else {
      avs.credentials.insert({ vault_id: vault.vault_id, key, value, type: "static" });
    }
  }

  for (const rawService of input.services ?? []) {
    const service = normalizeService(rawService, vault.vault_id);
    if (validateService(service)) continue;
    const existing = avs.services
      .findBy("vault_id", vault.vault_id)
      .find((candidate) => candidate.name === service.name);
    if (existing) {
      avs.services.update(existing.id, service);
    } else {
      avs.services.insert(service);
    }
  }
}

function upsertAgent(
  store: Store,
  input: {
    name: string;
    token?: string;
    role?: AgentVaultInstanceRole;
    vaults: Array<{ vault_name: string; vault_role: AgentVaultRole }>;
  },
): void {
  const avs = getAgentVaultStore(store);
  const existing = avs.agents.findOneBy("name", input.name);
  const data = {
    agent_id: existing?.agent_id ?? generateId("agt"),
    name: input.name,
    role: input.role ?? "no-access",
    status: "active" as const,
    token: input.token ?? existing?.token ?? generateId("av_agt"),
    vaults: input.vaults,
    created_by: "seed",
    token_expires_at: null,
    revoked_at: null,
  };
  if (existing) {
    avs.agents.update(existing.id, data);
  } else {
    avs.agents.insert(data);
  }
}
