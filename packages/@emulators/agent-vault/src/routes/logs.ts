import type { RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import { credentialKeysForService, formatService, htmlCell, jsonError, requireAuth } from "../helpers.js";

export function logRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/discover", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = c.req.header("x-vault") ?? c.req.query("vault") ?? "default";
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const services = avs()
      .services.findBy("vault_id", vault.vault_id)
      .map((service) => ({ name: service.name, host: formatService(service).host }));
    const availableCredentials = avs()
      .credentials.findBy("vault_id", vault.vault_id)
      .map((credential) => credential.key);

    return c.json({
      vault: vault.name,
      services,
      available_credentials: availableCredentials,
    });
  });

  app.get("/v1/vaults/:name/logs", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const limit = Math.min(200, Math.max(1, Number(c.req.query("limit") ?? 50) || 50));
    const before = Number(c.req.query("before") ?? 0) || 0;
    const after = Number(c.req.query("after") ?? 0) || 0;
    if (before > 0 && after > 0) return jsonError(c, 400, "before and after are mutually exclusive");

    let rows = avs()
      .requestLogs.findBy("vault_id", vault.vault_id)
      .filter((row) => !c.req.query("service") || row.matched_service === c.req.query("service"))
      .filter((row) => !c.req.query("ingress") || row.ingress === c.req.query("ingress"))
      .filter((row) => {
        const bucket = c.req.query("status_bucket");
        if (!bucket) return true;
        if (bucket === "2xx") return row.status >= 200 && row.status < 300;
        if (bucket === "4xx") return row.status >= 400 && row.status < 500;
        if (bucket === "5xx") return row.status >= 500 && row.status < 600;
        return true;
      });

    rows = rows.sort((a, b) => b.log_id - a.log_id);
    if (before > 0) rows = rows.filter((row) => row.log_id < before);
    if (after > 0) rows = rows.filter((row) => row.log_id > after).sort((a, b) => a.log_id - b.log_id);
    rows = rows.slice(0, limit);
    if (after > 0) rows = rows.reverse();

    const latestId = rows[0]?.log_id ?? after;
    const nextCursor = after === 0 && rows.length === limit ? rows[rows.length - 1]?.log_id : null;

    return c.json({
      logs: rows.map((row) => ({
        id: row.log_id,
        ingress: row.ingress,
        method: row.method,
        host: row.host,
        path: row.path,
        matched_service: row.matched_service,
        credential_keys: row.credential_keys,
        status: row.status,
        latency_ms: row.latency_ms,
        error_code: row.error_code,
        actor_type: row.actor_type,
        actor_id: row.actor_id,
        actor_name: row.actor_name || undefined,
        created_at: row.created_at,
      })),
      next_cursor: nextCursor,
      latest_id: latestId,
    });
  });

  app.get("/v1/vaults/:name/discovered-hosts", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const knownHosts = new Set(
      avs()
        .services.findBy("vault_id", vault.vault_id)
        .map((service) => service.host),
    );
    const discovered = avs()
      .requestLogs.findBy("vault_id", vault.vault_id)
      .filter((row) => row.host && !knownHosts.has(row.host))
      .map((row) => ({
        host: row.host,
        first_seen_at: row.created_at,
        last_seen_at: row.updated_at,
        request_count: 1,
      }));

    return c.json({ hosts: discovered });
  });

  app.post("/_agent-vault/logs", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const vaultName = typeof body.vault === "string" ? body.vault : "default";
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const serviceName = typeof body.matched_service === "string" ? body.matched_service : "";
    const service = serviceName
      ? avs()
          .services.findBy("vault_id", vault.vault_id)
          .find((candidate) => candidate.name === serviceName)
      : undefined;

    avs().requestLogs.insert({
      log_id:
        avs()
          .requestLogs.all()
          .reduce((max, row) => Math.max(max, row.log_id), 0) + 1,
      vault_id: vault.vault_id,
      ingress: "emulated",
      method: String(body.method ?? "GET"),
      host: String(body.host ?? service?.host ?? ""),
      path: String(body.path ?? "/"),
      matched_service: service?.name ?? serviceName,
      credential_keys: service ? credentialKeysForService(service) : [],
      status: typeof body.status === "number" ? body.status : 200,
      latency_ms: typeof body.latency_ms === "number" ? body.latency_ms : 0,
      error_code: typeof body.error_code === "string" ? body.error_code : "",
      actor_type: "user",
      actor_id: c.get("authUser")?.login ?? "admin",
      actor_name: c.get("authUser")?.login ?? "admin",
    });

    return c.json({ logged: true });
  });
}

export function table(headers: string[], rows: string[][], empty: string): string {
  if (rows.length === 0) {
    return `<div class="inspector-empty">${htmlCell(empty)}</div>`;
  }
  return `<table class="inspector-table"><thead><tr>${headers
    .map((header) => `<th>${htmlCell(header)}</th>`)
    .join("")}</tr></thead><tbody>${rows
    .map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`)
    .join("")}</tbody></table>`;
}
