import type { RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import {
  DEFAULT_VAULT_NAME,
  formatVault,
  jsonError,
  parseObjectBody,
  requireAuth,
  validateSlug,
  vaultId,
} from "../helpers.js";
import type { AgentVaultCredentialStoreSummary, AgentVaultUnmatchedHostPolicy } from "../entities.js";

export function vaultRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/v1/status", (c) => {
    return c.json({
      initialized: true,
      version: "emulate",
      base_url: ctx.baseUrl,
      default_vault: DEFAULT_VAULT_NAME,
      auth_required: true,
    });
  });

  app.get("/v1/vaults", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({ vaults: avs().vaults.all().map(formatVault) });
  });

  app.get("/v1/admin/vaults", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({ vaults: avs().vaults.all().map(formatVault) });
  });

  app.post("/v1/vaults", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const name = String(body.name ?? "");
    const nameError = validateSlug(name, "Vault name");
    if (nameError) return jsonError(c, 400, nameError);
    if (name === "users") return jsonError(c, 400, "This vault name is reserved");
    if (avs().vaults.findOneBy("name", name)) return jsonError(c, 409, `Vault ${JSON.stringify(name)} already exists`);

    const credentialStore = normalizeCredentialStore(body.credential_store);
    const vault = avs().vaults.insert({
      vault_id: vaultId(),
      name,
      unmatched_host_policy: "passthrough",
      credential_store: credentialStore,
    });

    return c.json(formatVault(vault), 201);
  });

  app.delete("/v1/vaults/:name", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    if (name === DEFAULT_VAULT_NAME) return jsonError(c, 400, "The default vault cannot be deleted");

    const vault = avs().vaults.findOneBy("name", name);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(name)} not found`);

    for (const credential of avs().credentials.findBy("vault_id", vault.vault_id)) {
      avs().credentials.delete(credential.id);
    }
    for (const service of avs().services.findBy("vault_id", vault.vault_id)) {
      avs().services.delete(service.id);
    }
    for (const session of avs().sessions.findBy("vault_id", vault.vault_id)) {
      avs().sessions.delete(session.id);
    }
    avs().vaults.delete(vault.id);

    return c.json({ name, deleted: true });
  });

  app.post("/v1/vaults/:name/rename", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const oldName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", oldName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(oldName)} not found`);

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const newName = String(body.name ?? "");
    const nameError = validateSlug(newName, "Vault name");
    if (nameError) return jsonError(c, 400, nameError);
    if (avs().vaults.findOneBy("name", newName))
      return jsonError(c, 409, `Vault ${JSON.stringify(newName)} already exists`);

    avs().vaults.update(vault.id, { name: newName });
    for (const agent of avs().agents.all()) {
      const grants = agent.vaults.map((grant) =>
        grant.vault_name === oldName ? { ...grant, vault_name: newName } : grant,
      );
      avs().agents.update(agent.id, { vaults: grants });
    }
    for (const session of avs().sessions.findBy("vault_id", vault.vault_id)) {
      avs().sessions.update(session.id, { vault_name: newName });
    }

    return c.json({
      message: `vault renamed from ${JSON.stringify(oldName)} to ${JSON.stringify(newName)}`,
      old_name: oldName,
      new_name: newName,
    });
  });

  app.get("/v1/vaults/:name/context", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", name);
    if (!vault) return jsonError(c, 404, "Vault not found");

    return c.json({
      vault_name: vault.name,
      vault_role: "admin",
      credential_store: vault.credential_store ?? undefined,
    });
  });

  app.get("/v1/vaults/:name/settings", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", name);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(name)} not found`);
    return c.json({
      vault: vault.name,
      unmatched_host_policy: vault.unmatched_host_policy,
    });
  });

  app.patch("/v1/vaults/:name/settings", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", name);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(name)} not found`);

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const policy = body.unmatched_host_policy as AgentVaultUnmatchedHostPolicy | undefined;
    if (policy !== undefined && policy !== "passthrough" && policy !== "deny") {
      return jsonError(c, 400, "unmatched_host_policy must be 'passthrough' or 'deny'");
    }

    const updated = avs().vaults.update(vault.id, {
      unmatched_host_policy: policy ?? vault.unmatched_host_policy,
    })!;
    return c.json({
      vault: updated.name,
      unmatched_host_policy: updated.unmatched_host_policy,
    });
  });

  app.get("/v1/instance/credential-stores", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({ available: ["builtin", "infisical"] });
  });

  app.post("/v1/vaults/:name/sync", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", name);
    if (!vault) return jsonError(c, 404, "Vault not found");

    return c.json({
      credential_store: vault.credential_store ?? { kind: "builtin", last_sync_status: "ok" },
    });
  });
}

function normalizeCredentialStore(value: unknown): AgentVaultCredentialStoreSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const kind = raw.kind === "infisical" ? "infisical" : raw.kind === "builtin" ? "builtin" : undefined;
  if (!kind) return null;
  const config =
    raw.config && typeof raw.config === "object" && !Array.isArray(raw.config)
      ? (raw.config as Record<string, unknown>)
      : undefined;
  return {
    kind,
    config,
    poll_interval_seconds: typeof raw.poll_interval_seconds === "number" ? raw.poll_interval_seconds : undefined,
    last_sync_status: "ok",
  };
}
