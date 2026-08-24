import type { Context, RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import {
  credentialKeysForService,
  formatService,
  jsonError,
  normalizeService,
  parseObjectBody,
  requireAuth,
  resolveServiceRef,
  validateService,
} from "../helpers.js";
import type { AgentVaultService } from "../entities.js";

export function serviceRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/v1/vaults/:name/services", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    return c.json({
      vault: vault.name,
      services: servicesForVault(vault.vault_id).map(formatService),
    });
  });

  app.get("/v1/vaults/:name/services/credential-usage", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const key = c.req.query("key");
    if (!key) return jsonError(c, 400, "Missing required query parameter: key");

    const services = servicesForVault(vault.vault_id)
      .filter((service) => credentialKeysForService(service).includes(key))
      .map((service) => ({ name: service.name, host: formatService(service).host }));

    return c.json({ services });
  });

  app.post("/v1/vaults/:name/services", async (c) => {
    const result = await readServicesRequest(c, decodeURIComponent(c.req.param("name")));
    if (result instanceof Response) return result;

    const { vault, incoming } = result;
    const existing = servicesForVault(vault.vault_id);
    const byName = new Map(existing.map((service) => [service.name, service]));
    const upserted: string[] = [];

    for (const service of incoming) {
      const previous = byName.get(service.name);
      if (previous) {
        avs().services.update(previous.id, service);
      } else {
        avs().services.insert(service);
      }
      upserted.push(service.name);
    }

    return c.json({
      vault: vault.name,
      upserted,
      services_count: servicesForVault(vault.vault_id).length,
    });
  });

  app.put("/v1/vaults/:name/services", async (c) => {
    const result = await readServicesRequest(c, decodeURIComponent(c.req.param("name")), true);
    if (result instanceof Response) return result;

    const { vault, incoming } = result;
    for (const service of servicesForVault(vault.vault_id)) {
      avs().services.delete(service.id);
    }
    for (const service of incoming) {
      avs().services.insert(service);
    }

    return c.json({
      vault: vault.name,
      services_count: incoming.length,
    });
  });

  app.delete("/v1/vaults/:name/services", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    for (const service of servicesForVault(vault.vault_id)) {
      avs().services.delete(service.id);
    }

    return c.json({ vault: vault.name, cleared: true });
  });

  app.patch("/v1/vaults/:name/services/:ref{.+}", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }
    if (typeof body.enabled !== "boolean")
      return jsonError(c, 400, "At least one patchable field is required (enabled)");

    const ref = decodeURIComponent(c.req.param("ref"));
    const resolved = resolveServiceRef(servicesForVault(vault.vault_id), ref);
    if (resolved.candidates) {
      return c.json(
        {
          error: `multiple services match host ${JSON.stringify(ref)}`,
          candidates: resolved.candidates.map(formatService),
        },
        409,
      );
    }
    if (!resolved.service) return jsonError(c, 404, `Service not found for ${JSON.stringify(ref)}`);

    const updated = avs().services.update(resolved.service.id, { enabled: body.enabled })!;
    return c.json({
      vault: vault.name,
      name: updated.name,
      host: formatService(updated).host,
      enabled: body.enabled,
    });
  });

  app.delete("/v1/vaults/:name/services/:ref{.+}", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const ref = decodeURIComponent(c.req.param("ref"));
    const resolved = resolveServiceRef(servicesForVault(vault.vault_id), ref);
    if (resolved.candidates) {
      return c.json(
        {
          error: `multiple services match host ${JSON.stringify(ref)}`,
          candidates: resolved.candidates.map(formatService),
        },
        409,
      );
    }
    if (!resolved.service) return jsonError(c, 404, `Service not found for ${JSON.stringify(ref)}`);

    const removed = resolved.service;
    avs().services.delete(removed.id);
    return c.json({
      vault: vault.name,
      removed: removed.name,
      removed_host: formatService(removed).host,
      services_count: servicesForVault(vault.vault_id).length,
    });
  });

  async function readServicesRequest(c: Context, vaultName: string, allowEmpty = false) {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const rawServices = Array.isArray(body.services) ? body.services : [];
    if (!allowEmpty && rawServices.length === 0) return jsonError(c, 400, "At least one service is required");

    const incoming: Array<Omit<AgentVaultService, "id" | "created_at" | "updated_at">> = [];
    const seen = new Set<string>();
    for (const raw of rawServices) {
      const service = normalizeService(raw as Record<string, unknown>, vault.vault_id);
      const validation = validateService(service);
      if (validation) return jsonError(c, 400, `Invalid services: ${validation}`);
      if (seen.has(service.name))
        return jsonError(c, 400, `Invalid services: duplicate name ${JSON.stringify(service.name)}`);
      seen.add(service.name);
      incoming.push(service);
    }

    return { vault, incoming };
  }

  function servicesForVault(vaultId: string): AgentVaultService[] {
    return avs().services.findBy("vault_id", vaultId);
  }
}
