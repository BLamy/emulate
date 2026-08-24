import type { RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import {
  DEFAULT_MITM_PORT,
  generateId,
  getCaCertificate,
  getMitmPort,
  jsonError,
  parseObjectBody,
  requireAuth,
  validateVaultRole,
} from "../helpers.js";

const MIN_TTL_SECONDS = 300;
const MAX_TTL_SECONDS = 604800;
const DEFAULT_TTL_SECONDS = 86400;

export function sessionRoutes(ctx: RouteContext): void {
  const { app, store, baseUrl } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.post("/v1/sessions", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const vaultName = String(body.vault ?? "");
    if (!vaultName) return jsonError(c, 400, "Vault is required");
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const requestedRole = body.vault_role ? String(body.vault_role) : "proxy";
    if (!validateVaultRole(requestedRole) || requestedRole !== "proxy") {
      return jsonError(c, 400, "vault_role must be 'proxy'");
    }

    const ttlSeconds = typeof body.ttl_seconds === "number" ? body.ttl_seconds : DEFAULT_TTL_SECONDS;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < MIN_TTL_SECONDS || ttlSeconds > MAX_TTL_SECONDS) {
      return jsonError(c, 400, `ttl_seconds must be between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS}`);
    }

    const label = sanitizeLabel(typeof body.label === "string" ? body.label : "");
    if (label.length > 100) return jsonError(c, 400, "label must be at most 100 characters");

    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const token = generateId("av_sess");
    avs().sessions.insert({
      public_id: generateId("sess"),
      token,
      vault_id: vault.vault_id,
      vault_name: vault.name,
      vault_role: "proxy",
      label,
      expires_at: expiresAt,
      created_by_id: c.get("authUser")?.login ?? "admin",
      created_by_type: "user",
    });

    return c.json({
      token,
      expires_at: expiresAt,
      av_addr: baseUrl,
    });
  });

  app.get("/v1/sessions", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = c.req.query("vault");
    if (!vaultName) return jsonError(c, 400, "vault is required");
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const sessions = avs()
      .sessions.findBy("vault_id", vault.vault_id)
      .map((session) => ({
        id: session.public_id,
        label: session.label || undefined,
        vault_role: session.vault_role,
        created_by: {
          id: session.created_by_id,
          type: session.created_by_type,
          display_name: session.created_by_id,
        },
        created_at: session.created_at,
        expires_at: session.expires_at,
      }));

    return c.json({ sessions });
  });

  app.delete("/v1/sessions/:id", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = c.req.query("vault");
    if (!vaultName) return jsonError(c, 400, "vault is required");
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const id = decodeURIComponent(c.req.param("id"));
    const session = avs()
      .sessions.findBy("vault_id", vault.vault_id)
      .find((candidate) => candidate.public_id === id || candidate.token === id);
    if (!session) return jsonError(c, 404, "Session not found");

    avs().sessions.delete(session.id);
    return c.json({ id, revoked: true });
  });

  app.get("/v1/mitm/ca.pem", (c) => {
    const port = getMitmPort(store);
    if (port <= 0) return c.text("MITM proxy is not enabled on this server\n", 404);

    c.header("X-MITM-Port", String(port || DEFAULT_MITM_PORT));
    c.header("Content-Type", "application/x-pem-file");
    c.header("Content-Disposition", `attachment; filename="agent-vault-ca.pem"`);
    return c.text(getCaCertificate(store));
  });
}

function sanitizeLabel(label: string): string {
  return label
    .trim()
    .split("")
    .filter((char) => {
      const code = char.charCodeAt(0);
      return code >= 0x20 && code !== 0x7f;
    })
    .join("");
}
