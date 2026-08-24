import type { RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import {
  formatCredential,
  jsonError,
  parseObjectBody,
  requireAuth,
  resolveVaultName,
  validateCredentialKey,
} from "../helpers.js";
import type { AgentVaultCredential } from "../entities.js";

export function credentialRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/v1/credentials", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = resolveVaultName(c);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const reveal = c.req.query("reveal") === "true";
    const key = c.req.query("key");
    const credentials = avs()
      .credentials.findBy("vault_id", vault.vault_id)
      .filter((credential) => !key || credential.key === key);

    if (reveal && key && credentials.length === 0) {
      return jsonError(c, 404, `Credential ${JSON.stringify(key)} not found`);
    }

    return c.json({
      keys: credentials.map((credential) => credential.key),
      credentials: credentials.map((credential) => formatCredentialForList(credential, reveal)),
    });
  });

  app.post("/v1/credentials", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const vaultName = resolveVaultName(c, body);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const credentials =
      body.credentials && typeof body.credentials === "object" && !Array.isArray(body.credentials)
        ? (body.credentials as Record<string, unknown>)
        : {};
    if (Object.keys(credentials).length === 0) return jsonError(c, 400, "Credentials map is required");

    const set: string[] = [];
    for (const [key, value] of Object.entries(credentials)) {
      const keyError = validateCredentialKey(key);
      if (keyError) return jsonError(c, 400, keyError);

      const existing = avs()
        .credentials.findBy("vault_id", vault.vault_id)
        .find((credential) => credential.key === key);
      if (existing) {
        avs().credentials.update(existing.id, { value: String(value), type: "static" });
      } else {
        avs().credentials.insert({
          vault_id: vault.vault_id,
          key,
          value: String(value),
          type: "static",
        });
      }
      set.push(key);
    }

    return c.json({ set });
  });

  app.delete("/v1/credentials", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const vaultName = resolveVaultName(c, body);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const keys = Array.isArray(body.keys) ? body.keys.map(String) : [];
    if (keys.length === 0) return jsonError(c, 400, "Keys array is required");
    for (const key of keys) {
      const keyError = validateCredentialKey(key);
      if (keyError) return jsonError(c, 400, keyError);
    }

    const deleted: string[] = [];
    for (const key of keys) {
      const existing = avs()
        .credentials.findBy("vault_id", vault.vault_id)
        .find((credential) => credential.key === key);
      if (existing) {
        avs().credentials.delete(existing.id);
        deleted.push(key);
      }
    }

    return c.json({ deleted });
  });

  function formatCredentialForList(credential: AgentVaultCredential, reveal: boolean) {
    const base = formatCredential(credential, reveal);
    if (credential.type !== "oauth") return base;
    const oauth = avs()
      .oauthCredentials.findBy("vault_id", credential.vault_id)
      .find((candidate) => candidate.key === credential.key);
    return {
      ...base,
      connected_at: oauth?.connected_at ?? undefined,
      last_refreshed_at: oauth?.last_refreshed_at ?? undefined,
      last_refresh_error: oauth?.last_refresh_error ?? undefined,
      authorization_url: oauth?.authorization_url,
      token_url: oauth?.token_url,
      client_id: oauth?.client_id,
      scopes: oauth?.scopes,
      token_auth_method: oauth?.token_auth_method,
      client_secret: oauth ? "••••••••" : undefined,
      access_token: reveal ? oauth?.access_token : undefined,
      refresh_token: reveal ? oauth?.refresh_token : undefined,
    };
  }
}
