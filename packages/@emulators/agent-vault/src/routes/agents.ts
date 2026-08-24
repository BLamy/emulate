import type { Context, RouteContext } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import { generateId, jsonError, parseObjectBody, requireAuth, validateSlug, validateVaultRole } from "../helpers.js";
import type { AgentVaultAgentGrant, AgentVaultInstanceRole } from "../entities.js";

export function agentRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/v1/agents", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({ agents: avs().agents.all().map(formatAgentListItem) });
  });

  app.post("/v1/agents", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const name = String(body.name ?? "");
    const nameError = validateSlug(name, "Agent name");
    if (nameError) return jsonError(c, 400, nameError);
    if (avs().agents.findOneBy("name", name))
      return jsonError(c, 409, `An agent named ${JSON.stringify(name)} already exists`);

    const role = normalizeInstanceRole(body.role);
    if (!role) return jsonError(c, 400, "Role must be one of: owner, member, no-access");

    const grants = normalizeVaultGrants(body.vaults);
    for (const grant of grants) {
      if (!avs().vaults.findOneBy("name", grant.vault_name)) {
        return jsonError(c, 404, `Vault ${JSON.stringify(grant.vault_name)} not found`);
      }
    }

    const token = generateId("av_agt");
    const agent = avs().agents.insert({
      agent_id: generateId("agt"),
      name,
      role,
      status: "active",
      token,
      vaults: grants,
      created_by: c.get("authUser")?.login ?? "admin",
      token_expires_at: null,
      revoked_at: null,
    });

    return c.json(
      {
        av_agent_token: agent.token,
        name: agent.name,
        role: agent.role,
        vaults: agent.vaults,
        created_at: agent.created_at,
      },
      201,
    );
  });

  app.get("/v1/agents/:name", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");
    return c.json({
      name: agent.name,
      role: agent.role,
      status: agent.status,
      vaults: agent.vaults,
      created_by: agent.created_by,
      created_at: agent.created_at,
      updated_at: agent.updated_at,
      revoked_at: agent.revoked_at ?? undefined,
      active_tokens: agent.status === "active" ? 1 : 0,
      token_expires_at: agent.token_expires_at ?? undefined,
    });
  });

  app.delete("/v1/agents/:name", (c) => revokeAgent(c, "revoke"));
  app.post("/v1/agents/:name/delete", (c) => deleteAgent(c));

  app.post("/v1/agents/:name/rotate", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");
    if (agent.status !== "active") return jsonError(c, 409, "Agent is revoked");

    const token = generateId("av_agt");
    const updated = avs().agents.update(agent.id, { token })!;
    return c.json({
      av_agent_token: updated.token,
      name: updated.name,
      rotated_at: new Date().toISOString(),
    });
  });

  app.post("/v1/agents/:name/rename", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const nextName = String(body.name ?? "");
    const nameError = validateSlug(nextName, "Agent name");
    if (nameError) return jsonError(c, 400, nameError);
    if (avs().agents.findOneBy("name", nextName))
      return jsonError(c, 409, `An agent named ${JSON.stringify(nextName)} already exists`);

    avs().agents.update(agent.id, { name: nextName });
    return c.json({
      message: `agent renamed from ${JSON.stringify(name)} to ${JSON.stringify(nextName)}`,
      old_name: name,
      new_name: nextName,
    });
  });

  app.post("/v1/agents/:name/role", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");

    let body: Record<string, unknown>;
    try {
      body = await parseObjectBody(c);
    } catch {
      return jsonError(c, 400, "Invalid request body");
    }

    const role = normalizeInstanceRole(body.role);
    if (!role) return jsonError(c, 400, "Role must be one of: owner, member, no-access");
    avs().agents.update(agent.id, { role });
    return c.json({ name, role });
  });

  app.get("/v1/vaults/:name/agents", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const vaultName = decodeURIComponent(c.req.param("name"));
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);

    const agents = avs()
      .agents.all()
      .filter((agent) => agent.vaults.some((grant) => grant.vault_name === vaultName))
      .map((agent) => ({
        name: agent.name,
        agent_id: agent.agent_id,
        vault_role: agent.vaults.find((grant) => grant.vault_name === vaultName)?.vault_role ?? "proxy",
        status: agent.status,
      }));
    return c.json({ agents });
  });

  app.post("/v1/vaults/:name/agents", async (c) => {
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

    const agentName = String(body.name ?? "");
    const agent = avs().agents.findOneBy("name", agentName);
    if (!agent) return jsonError(c, 404, `Agent ${JSON.stringify(agentName)} not found`);
    const role = body.role ? String(body.role) : "proxy";
    if (!validateVaultRole(role)) return jsonError(c, 400, "Role must be one of: proxy, member, admin");
    if (agent.vaults.some((grant) => grant.vault_name === vaultName)) {
      return jsonError(
        c,
        409,
        `Agent ${JSON.stringify(agentName)} already has access to vault ${JSON.stringify(vaultName)}`,
      );
    }
    avs().agents.update(agent.id, {
      vaults: [...agent.vaults, { vault_name: vault.name, vault_role: role }],
    });
    return c.json(
      {
        message: `agent ${JSON.stringify(agentName)} added to vault ${JSON.stringify(vaultName)} with role ${JSON.stringify(role)}`,
      },
      201,
    );
  });

  function revokeAgent(c: Context, _action: string) {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");
    if (agent.status !== "active") return jsonError(c, 409, "Agent is already revoked");
    avs().agents.update(agent.id, { status: "revoked", revoked_at: new Date().toISOString() });
    return c.json({ message: `agent ${JSON.stringify(name)} revoked` });
  }

  function deleteAgent(c: Context) {
    const auth = requireAuth(c);
    if (auth) return auth;

    const name = decodeURIComponent(c.req.param("name"));
    const agent = avs().agents.findOneBy("name", name);
    if (!agent) return jsonError(c, 404, "Agent not found");
    avs().agents.delete(agent.id);
    return c.json({ message: `agent ${JSON.stringify(name)} deleted` });
  }
}

function normalizeInstanceRole(value: unknown): AgentVaultInstanceRole | null {
  const role = value ? String(value) : "no-access";
  return role === "owner" || role === "member" || role === "no-access" ? role : null;
}

function normalizeVaultGrants(value: unknown): AgentVaultAgentGrant[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((grant) => {
      const raw = grant && typeof grant === "object" && !Array.isArray(grant) ? (grant as Record<string, unknown>) : {};
      const vaultName = String(raw.vault_name ?? raw.vault ?? "");
      const role = raw.vault_role ? String(raw.vault_role) : "proxy";
      return validateVaultRole(role) && vaultName ? { vault_name: vaultName, vault_role: role } : null;
    })
    .filter((grant): grant is AgentVaultAgentGrant => grant !== null);
}

function formatAgentListItem(agent: import("../entities.js").AgentVaultAgent) {
  return {
    name: agent.name,
    role: agent.role,
    status: agent.status,
    vaults: agent.vaults,
    created_at: agent.created_at,
    revoked_at: agent.revoked_at ?? undefined,
    token_expires_at: agent.token_expires_at ?? undefined,
  };
}
