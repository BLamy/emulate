import type { Context, RouteContext, Store } from "@emulators/core";
import { getAgentVaultStore, type AgentVaultStore } from "../store.js";
import {
  DEFAULT_VAULT_NAME,
  generateId,
  jsonError,
  normalizeService,
  parseObjectBody,
  requireAuth,
  validateCredentialKey,
  validateService,
  validateVaultRole,
} from "../helpers.js";
import type {
  AgentVaultCredential,
  AgentVaultCredentialStoreSummary,
  AgentVaultInstanceRole,
  AgentVaultOAuthCredential,
  AgentVaultProposal,
  AgentVaultRole,
  AgentVaultUser,
  AgentVaultUserGrant,
  AgentVaultUserInvite,
  AgentVaultVault,
} from "../entities.js";

const OWNER_EMAIL = "owner@example.com";
const DEFAULT_RATE_LIMIT = {
  tiers: {
    AUTH: { capacity: 60, refill_per_second: 1, source: "default" },
    AUTHED: { capacity: 600, refill_per_second: 10, source: "default" },
    PROXY: { capacity: 1200, refill_per_second: 20, source: "default" },
  },
  operator_pinned: false,
};

const SERVICE_CATALOG = [
  catalog("anthropic", "Anthropic", "api.anthropic.com", "Claude API", "api-key", "ANTHROPIC_API_KEY", {
    header: "x-api-key",
  }),
  catalog("github", "GitHub", "api.github.com", "GitHub REST API", "bearer", "GITHUB_TOKEN"),
  catalog("linear", "Linear", "api.linear.app", "Project management and issue tracking", "bearer", "LINEAR_API_KEY"),
  catalog("openai", "OpenAI", "api.openai.com", "OpenAI / ChatGPT API", "bearer", "OPENAI_API_KEY"),
  catalog("resend", "Resend", "api.resend.com", "Email API for developers", "bearer", "RESEND_API_KEY"),
  catalog("slack", "Slack", "slack.com", "Slack Web API", "bearer", "SLACK_TOKEN"),
  catalog("stripe", "Stripe", "api.stripe.com", "Payment processing API", "bearer", "STRIPE_KEY"),
  catalog("twilio", "Twilio", "api.twilio.com", "Communication APIs", "basic", "TWILIO_AUTH_TOKEN"),
  catalog("vercel", "Vercel", "api.vercel.com", "Vercel deployment platform", "bearer", "VERCEL_TOKEN"),
];

export function managementRoutes(ctx: RouteContext): void {
  const { app, store, baseUrl } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/health", (c) => c.json({ ok: true, initialized: true }));

  app.get("/v1/auth/me", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;

    const token = c.get("authToken");
    const agent = token ? avs().agents.findOneBy("token", token) : undefined;
    if (agent) {
      return c.json({
        type: "agent",
        agent_name: agent.name,
        role: agent.role,
        is_owner: agent.role === "owner",
      });
    }

    const user = ensureUser(avs(), currentEmail(c));
    return c.json({ type: "user", email: user.email, role: user.role, is_owner: user.role === "owner" });
  });

  app.post("/v1/auth/register", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;

    const email = String(body.email ?? "").trim() || OWNER_EMAIL;
    const existing = avs().users.findOneBy("email", email);
    const role: AgentVaultInstanceRole = avs().users.all().length === 0 ? "owner" : "member";
    const user = existing ?? avs().users.insert({ email, role, vaults: defaultUserGrants(avs(), role) });
    return c.json(
      {
        email: user.email,
        role: user.role,
        requires_verification: false,
        authenticated: true,
        message: existing ? "Account already exists." : "Account created.",
        token: generateId("av_user"),
        expires_at: oneDayFromNow(),
      },
      201,
    );
  });

  app.post("/v1/auth/verify", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const email = String(body.email ?? "").trim() || OWNER_EMAIL;
    const user = ensureUser(avs(), email, "member");
    return c.json({
      email: user.email,
      role: user.role,
      authenticated: true,
      message: "Account verified.",
      token: generateId("av_user"),
      expires_at: oneDayFromNow(),
    });
  });

  app.post("/v1/auth/resend-verification", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    return c.json({
      email: String(body.email ?? ""),
      email_sent: false,
      message: "Verification code logged by emulator.",
    });
  });

  app.post("/v1/auth/login", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const email = String(body.email ?? "").trim() || OWNER_EMAIL;
    const user = ensureUser(avs(), email, email === OWNER_EMAIL ? "owner" : "member");
    return c.json({
      email: user.email,
      role: user.role,
      authenticated: true,
      token: generateId("av_user"),
      expires_at: oneDayFromNow(),
    });
  });

  app.post("/v1/auth/logout", (c) => c.json({ status: "ok" }));
  app.post("/v1/auth/forgot-password", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    return c.json({
      email: String(body.email ?? ""),
      email_sent: false,
      message: "If this email exists, a reset code has been logged by the emulator.",
    });
  });
  app.post("/v1/auth/reset-password", (c) => c.json({ message: "Password reset successfully.", authenticated: true }));
  app.post("/v1/auth/change-password", (c) => c.json({ status: "ok" }));
  app.delete("/v1/auth/account", (c) => c.json({ status: "deleted", email: currentEmail(c) }));
  app.get("/v1/auth/sessions", (c) =>
    c.json({
      sessions: [
        {
          id: c.get("authToken") ?? "av_user_default",
          current: true,
          device_label: "emulate",
          created_at: new Date().toISOString(),
          expires_at: oneDayFromNow(),
        },
      ],
    }),
  );
  app.delete("/v1/auth/sessions/:id", (c) => c.json({ id: decodeURIComponent(c.req.param("id")), revoked: true }));

  app.get("/v1/service-catalog", (c) => c.json({ services: SERVICE_CATALOG }));
  app.get("/v1/skills/cli", (c) =>
    c.text(
      [
        "# Agent Vault CLI Skill",
        "",
        "Use AGENT_VAULT_ADDR and AGENT_VAULT_TOKEN to call the local Agent Vault emulator.",
        "Create proposals when access is needed, or use configured services through the proxy in real Agent Vault.",
      ].join("\n"),
      200,
      { "Content-Type": "text/markdown; charset=utf-8" },
    ),
  );

  app.get("/v1/users", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    ensureUser(avs(), OWNER_EMAIL, "owner");
    return c.json({ users: avs().users.all().map(formatUser) });
  });

  app.get("/v1/admin/users/:email", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const email = decodeURIComponent(c.req.param("email"));
    const user = avs().users.findOneBy("email", email);
    if (!user) return jsonError(c, 404, `User ${JSON.stringify(email)} not found`);
    return c.json(formatUser(user));
  });

  app.delete("/v1/admin/users/:email", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const email = decodeURIComponent(c.req.param("email"));
    const user = avs().users.findOneBy("email", email);
    if (!user) return jsonError(c, 404, `User ${JSON.stringify(email)} not found`);
    avs().users.delete(user.id);
    return c.json({ status: "removed", email });
  });

  app.post("/v1/admin/users/:email/role", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const email = decodeURIComponent(c.req.param("email"));
    const user = avs().users.findOneBy("email", email);
    if (!user) return jsonError(c, 404, `User ${JSON.stringify(email)} not found`);
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const role = normalizeInstanceRole(body.role);
    if (!role) return jsonError(c, 400, "Role must be one of: owner, member, no-access");
    avs().users.update(user.id, { role });
    return c.json({ email, role });
  });

  app.get("/v1/users/invites", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const status = c.req.query("status");
    return c.json({
      invites: avs()
        .userInvites.all()
        .filter((invite) => !status || invite.status === status)
        .map(formatInvite),
    });
  });

  app.post("/v1/users/invites", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const email = String(body.email ?? "").trim();
    if (!email) return jsonError(c, 400, "email is required");
    const role = normalizeInstanceRole(body.role) ?? "member";
    const grants = normalizeUserGrants(body.vaults);
    const invite = avs().userInvites.insert({
      token: generateId("av_inv"),
      email,
      role,
      vaults: grants,
      status: "pending",
      expires_at: new Date(Date.now() + 7 * 86400 * 1000).toISOString(),
    });
    return c.json(formatInvite(invite), 201);
  });

  app.delete("/v1/users/invites/:token", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const token = decodeURIComponent(c.req.param("token"));
    const invite = avs().userInvites.findOneBy("token", token);
    if (!invite) return jsonError(c, 404, "Invite not found");
    avs().userInvites.update(invite.id, { status: "revoked" });
    return c.json({ token, status: "revoked" });
  });

  app.post("/v1/users/invites/:token/reinvite", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const token = decodeURIComponent(c.req.param("token"));
    const invite = avs().userInvites.findOneBy("token", token);
    if (!invite) return jsonError(c, 404, "Invite not found");
    const updated = avs().userInvites.update(invite.id, {
      status: "pending",
      expires_at: new Date(Date.now() + 7 * 86400 * 1000).toISOString(),
    })!;
    return c.json(formatInvite(updated));
  });

  app.get("/v1/users/invites/:token/details", (c) => {
    const token = decodeURIComponent(c.req.param("token"));
    const invite = avs().userInvites.findOneBy("token", token);
    if (!invite) return jsonError(c, 404, "Invite not found");
    return c.json({
      email: invite.email,
      role: invite.role,
      vaults: invite.vaults,
      needs_account: !avs().users.findOneBy("email", invite.email),
      ...(invite.status !== "pending"
        ? {
            error: true,
            error_title: invite.status,
            error_message: `This invitation is ${invite.status}.`,
          }
        : {}),
    });
  });

  app.post("/v1/users/invites/:token/accept", async (c) => {
    const token = decodeURIComponent(c.req.param("token"));
    const invite = avs().userInvites.findOneBy("token", token);
    if (!invite) return jsonError(c, 404, "Invite not found");
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const user = ensureUser(avs(), invite.email, invite.role);
    avs().users.update(user.id, { role: invite.role, vaults: mergeGrants(user.vaults, invite.vaults) });
    avs().userInvites.update(invite.id, { status: "accepted" });
    return c.json({
      email: invite.email,
      authenticated: true,
      token: generateId("av_user"),
      expires_at: oneDayFromNow(),
    });
  });

  app.get("/v1/vaults/:name/users", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    return c.json({
      users: avs()
        .users.all()
        .filter((user) => user.vaults.some((grant) => grant.vault_name === vault.name))
        .map((user) => {
          const grant = user.vaults.find((entry) => entry.vault_name === vault.name);
          return {
            email: user.email,
            role: user.role,
            vault_role: grant?.vault_role ?? "proxy",
            created_at: user.created_at,
          };
        }),
    });
  });

  app.post("/v1/vaults/:name/users", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const email = String(body.email ?? "");
    if (!email) return jsonError(c, 400, "email is required");
    const role = body.role ? String(body.role) : "proxy";
    if (!validateVaultRole(role)) return jsonError(c, 400, "Role must be one of: proxy, member, admin");
    const user = ensureUser(avs(), email, "member");
    avs().users.update(user.id, { vaults: mergeGrants(user.vaults, [{ vault_name: vault.name, vault_role: role }]) });
    return c.json({ email, vault: vault.name, vault_role: role }, 201);
  });

  app.delete("/v1/vaults/:name/users/:email", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const email = decodeURIComponent(c.req.param("email"));
    const user = avs().users.findOneBy("email", email);
    if (!user) return jsonError(c, 404, `User ${JSON.stringify(email)} not found`);
    avs().users.update(user.id, { vaults: user.vaults.filter((grant) => grant.vault_name !== vault.name) });
    return c.json({ email, vault: vault.name, removed: true });
  });

  app.post("/v1/vaults/:name/users/:email/role", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const email = decodeURIComponent(c.req.param("email"));
    const user = avs().users.findOneBy("email", email);
    if (!user) return jsonError(c, 404, `User ${JSON.stringify(email)} not found`);
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const role = body.role ? String(body.role) : "";
    if (!validateVaultRole(role)) return jsonError(c, 400, "Role must be one of: proxy, member, admin");
    avs().users.update(user.id, { vaults: mergeGrants(user.vaults, [{ vault_name: vault.name, vault_role: role }]) });
    return c.json({ email, vault: vault.name, vault_role: role });
  });

  app.post("/v1/vaults/:name/join", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const user = ensureUser(avs(), currentEmail(c));
    avs().users.update(user.id, {
      vaults: mergeGrants(user.vaults, [{ vault_name: vault.name, vault_role: "member" }]),
    });
    return c.json({ vault: vault.name, joined: true });
  });

  app.post("/v1/vaults/:name/leave", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const user = ensureUser(avs(), currentEmail(c));
    avs().users.update(user.id, { vaults: user.vaults.filter((grant) => grant.vault_name !== vault.name) });
    return c.json({ vault: vault.name, left: true });
  });

  app.delete("/v1/vaults/:name/agents/:agentName", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const agentName = decodeURIComponent(c.req.param("agentName"));
    const agent = avs().agents.findOneBy("name", agentName);
    if (!agent) return jsonError(c, 404, "Agent not found");
    avs().agents.update(agent.id, { vaults: agent.vaults.filter((grant) => grant.vault_name !== vault.name) });
    return c.json({ agent: agentName, vault: vault.name, removed: true });
  });

  app.post("/v1/vaults/:name/agents/:agentName/role", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const agentName = decodeURIComponent(c.req.param("agentName"));
    const agent = avs().agents.findOneBy("name", agentName);
    if (!agent) return jsonError(c, 404, "Agent not found");
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const role = body.role ? String(body.role) : "";
    if (!validateVaultRole(role)) return jsonError(c, 400, "Role must be one of: proxy, member, admin");
    const vaults = mergeGrants(agent.vaults, [{ vault_name: vault.name, vault_role: role }]);
    avs().agents.update(agent.id, { vaults });
    return c.json({ agent: agentName, vault: vault.name, vault_role: role });
  });

  app.patch("/v1/vaults/:name/credential-store", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vault = findVault(c, avs());
    if (vault instanceof Response) return vault;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const storeSummary = normalizeCredentialStore(body.credential_store ?? body);
    const updated = avs().vaults.update(vault.id, { credential_store: storeSummary })!;
    return c.json({ vault: updated.name, credential_store: updated.credential_store ?? { kind: "builtin" } });
  });

  app.get("/v1/admin/settings", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json(readSettings(store));
  });

  app.put("/v1/admin/settings", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const current = readSettings(store);
    const next = {
      ...current,
      ...(Array.isArray(body.allowed_email_domains)
        ? { allowed_email_domains: body.allowed_email_domains.map(String) }
        : {}),
      ...(typeof body.invite_only === "boolean" ? { invite_only: body.invite_only } : {}),
      ...(body.rate_limit && typeof body.rate_limit === "object" ? { rate_limit: body.rate_limit } : {}),
    };
    store.setData("agent-vault.settings", next);
    return c.json(next);
  });

  app.post("/v1/admin/settings/rate-limit/preview", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    return c.json({ valid: true, rate_limit: body.rate_limit ?? DEFAULT_RATE_LIMIT });
  });

  app.post("/v1/admin/email/test", async (c) => {
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    return c.json({ message: "Test email accepted by emulator", to: String(body.to ?? currentEmail(c)) });
  });

  app.post("/v1/credentials/oauth/connect", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const vaultName = String(body.vault ?? DEFAULT_VAULT_NAME);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);
    const key = String(body.key ?? "");
    const keyError = validateCredentialKey(key);
    if (keyError) return jsonError(c, 400, keyError);
    const oauth = upsertOAuthCredential(avs(), vault, key, body);
    const state = generateId("av_oast");
    const authorizationUrl = new URL(oauth.authorization_url || `${baseUrl}/oauth/complete`);
    authorizationUrl.searchParams.set("client_id", oauth.client_id);
    authorizationUrl.searchParams.set("redirect_uri", `${baseUrl}/v1/oauth/callback`);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("state", state);
    if (oauth.scopes) authorizationUrl.searchParams.set("scope", oauth.scopes);
    return c.json({ authorization_url: authorizationUrl.toString() });
  });

  app.get("/v1/oauth/callback", (c) => {
    const key = c.req.query("key") ?? "";
    const vault = c.req.query("vault") ?? DEFAULT_VAULT_NAME;
    return c.redirect(
      `/oauth/complete?vault=${encodeURIComponent(vault)}&key=${encodeURIComponent(key)}&status=success`,
    );
  });

  app.get("/v1/credentials/oauth/status", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const vaultName = c.req.query("vault") ?? DEFAULT_VAULT_NAME;
    const key = c.req.query("key") ?? "";
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);
    const oauth = avs()
      .oauthCredentials.findBy("vault_id", vault.vault_id)
      .find((candidate) => candidate.key === key);
    return c.json({
      connected: Boolean(oauth?.connected_at || oauth?.access_token),
      key,
      vault: vault.name,
      connected_at: oauth?.connected_at ?? undefined,
      last_refreshed_at: oauth?.last_refreshed_at ?? undefined,
      last_refresh_error: oauth?.last_refresh_error ?? undefined,
    });
  });

  app.post("/v1/credentials/oauth/tokens", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const vaultName = String(body.vault ?? DEFAULT_VAULT_NAME);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);
    const key = String(body.key ?? "");
    const keyError = validateCredentialKey(key);
    if (keyError) return jsonError(c, 400, keyError);
    const oauth = upsertOAuthCredential(avs(), vault, key, body);
    const now = new Date().toISOString();
    avs().oauthCredentials.update(oauth.id, {
      access_token: String(body.access_token ?? oauth.access_token ?? ""),
      refresh_token: String(body.refresh_token ?? oauth.refresh_token ?? ""),
      connected_at: oauth.connected_at ?? now,
      last_refreshed_at: now,
      last_refresh_error: null,
    });
    upsertCredential(avs(), vault.vault_id, key, "", "oauth");
    return c.json({ key, type: "oauth", connected: true });
  });

  app.post("/v1/proposals", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    const vaultName = c.req.header("x-vault") ?? String(body.vault ?? DEFAULT_VAULT_NAME);
    const vault = avs().vaults.findOneBy("name", vaultName);
    if (!vault) return jsonError(c, 404, `Vault ${JSON.stringify(vaultName)} not found`);
    const proposal = createProposal(avs(), vault, body, currentEmail(c));
    return c.json(
      {
        id: proposal.proposal_id,
        status: proposal.status,
        vault: proposal.vault_name,
        approval_url: `${baseUrl}/approve/${proposal.proposal_id}?token=${proposal.approval_token}`,
        message: `Proposal created. Approve here: ${baseUrl}/approve/${proposal.proposal_id}?token=${proposal.approval_token}`,
      },
      201,
    );
  });

  app.get("/v1/proposals", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({ proposals: filterProposals(c, avs()).map(formatProposal) });
  });

  app.get("/v1/proposals/approve-details", (c) => {
    const token = c.req.query("token") ?? "";
    const id = Number(c.req.query("id") ?? 0);
    const proposal = avs()
      .proposals.all()
      .find((candidate) => candidate.approval_token === token || candidate.proposal_id === id);
    if (!proposal) return jsonError(c, 404, "Invalid or expired approval link");
    return c.json({
      proposal_id: proposal.proposal_id,
      vault: proposal.vault_name,
      status: proposal.status,
      user_message: proposal.user_message,
      message: proposal.message,
      services: JSON.parse(proposal.services_json),
      credentials: JSON.parse(proposal.credentials_json),
      created_at: proposal.created_at,
      agent_name: proposal.actor_name,
      authenticated: Boolean(c.get("authUser")),
      can_approve: true,
      user_email: currentEmail(c),
    });
  });

  app.get("/v1/proposals/:id", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const proposal = proposalByParam(c, avs());
    if (!proposal) return jsonError(c, 404, "Proposal not found");
    return c.json(formatProposal(proposal));
  });

  app.get("/v1/admin/proposals", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    return c.json({
      proposals: filterProposals(c, avs()).map(formatProposal),
      total: filterProposals(c, avs()).length,
    });
  });

  app.get("/v1/admin/proposals/:id", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const proposal = proposalByParam(c, avs());
    if (!proposal) return jsonError(c, 404, "Proposal not found");
    return c.json(formatProposal(proposal));
  });

  app.post("/v1/admin/proposals/:id/approve", async (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const proposal = proposalByParam(c, avs());
    if (!proposal) return jsonError(c, 404, "Proposal not found");
    const body = await readBodyOrError(c);
    if (body instanceof Response) return body;
    applyProposal(avs(), proposal, body);
    avs().proposals.update(proposal.id, { status: "approved", resolved_at: new Date().toISOString() });
    return c.json({ id: proposal.proposal_id, status: "approved" });
  });

  app.post("/v1/admin/proposals/:id/reject", (c) => {
    const auth = requireAuth(c);
    if (auth) return auth;
    const proposal = proposalByParam(c, avs());
    if (!proposal) return jsonError(c, 404, "Proposal not found");
    avs().proposals.update(proposal.id, { status: "rejected", resolved_at: new Date().toISOString() });
    return c.json({ id: proposal.proposal_id, status: "rejected" });
  });
}

export function seedManagementDefaults(store: Store): void {
  const avs = getAgentVaultStore(store);
  ensureUser(avs, OWNER_EMAIL, "owner");
}

async function readBodyOrError(c: Context): Promise<Record<string, unknown> | Response> {
  try {
    return await parseObjectBody(c);
  } catch {
    return jsonError(c, 400, "Invalid request body");
  }
}

function currentEmail(c: Context): string {
  const login = c.get("authUser")?.login;
  return login && login.includes("@") ? login : OWNER_EMAIL;
}

function ensureUser(avs: AgentVaultStore, email: string, role: AgentVaultInstanceRole = "owner"): AgentVaultUser {
  const existing = avs.users.findOneBy("email", email);
  if (existing) return existing;
  return avs.users.insert({
    email,
    role,
    vaults: defaultUserGrants(avs, role),
  });
}

function defaultUserGrants(avs: AgentVaultStore, role: AgentVaultInstanceRole): AgentVaultUserGrant[] {
  const vaultRole: AgentVaultRole = role === "owner" ? "admin" : "member";
  return avs.vaults.all().map((vault) => ({ vault_name: vault.name, vault_role: vaultRole }));
}

function formatUser(user: AgentVaultUser) {
  return {
    email: user.email,
    role: user.role,
    vaults: user.vaults,
    created_at: user.created_at,
  };
}

function normalizeInstanceRole(value: unknown): AgentVaultInstanceRole | null {
  const role = value ? String(value) : "no-access";
  return role === "owner" || role === "member" || role === "no-access" ? role : null;
}

function normalizeUserGrants(value: unknown): AgentVaultUserGrant[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const raw = item && typeof item === "object" && !Array.isArray(item) ? (item as Record<string, unknown>) : {};
    const vaultName = String(raw.vault_name ?? raw.vault ?? "");
    const role = raw.vault_role ? String(raw.vault_role) : "member";
    return vaultName && validateVaultRole(role) ? [{ vault_name: vaultName, vault_role: role }] : [];
  });
}

function mergeGrants<T extends { vault_name: string; vault_role: AgentVaultRole }>(existing: T[], incoming: T[]): T[] {
  const byVault = new Map(existing.map((grant) => [grant.vault_name, grant]));
  for (const grant of incoming) byVault.set(grant.vault_name, grant);
  return [...byVault.values()];
}

function formatInvite(invite: AgentVaultUserInvite) {
  return {
    token: invite.token,
    email: invite.email,
    role: invite.role,
    vaults: invite.vaults,
    status: invite.status,
    expires_at: invite.expires_at,
    created_at: invite.created_at,
  };
}

function findVault(c: Context, avs: AgentVaultStore): AgentVaultVault | Response {
  const name = decodeURIComponent(c.req.param("name"));
  const vault = avs.vaults.findOneBy("name", name);
  return vault ?? jsonError(c, 404, `Vault ${JSON.stringify(name)} not found`);
}

function normalizeCredentialStore(value: unknown): AgentVaultCredentialStoreSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { kind: "builtin", last_sync_status: "ok" };
  const raw = value as Record<string, unknown>;
  const kind = raw.kind === "infisical" ? "infisical" : "builtin";
  return {
    kind,
    config:
      raw.config && typeof raw.config === "object" && !Array.isArray(raw.config)
        ? (raw.config as Record<string, unknown>)
        : undefined,
    poll_interval_seconds: typeof raw.poll_interval_seconds === "number" ? raw.poll_interval_seconds : undefined,
    last_sync_status: "ok",
    last_synced_at: new Date().toISOString(),
  };
}

function readSettings(store: Store) {
  return (
    store.getData<Record<string, unknown>>("agent-vault.settings") ?? {
      allowed_email_domains: [],
      invite_only: false,
      smtp_configured: false,
      rate_limit: DEFAULT_RATE_LIMIT,
    }
  );
}

function catalog(
  id: string,
  name: string,
  host: string,
  description: string,
  authType: string,
  suggestedCredentialKey: string,
  extras: Record<string, string> = {},
) {
  return {
    id,
    name,
    host,
    description,
    auth_type: authType,
    suggested_credential_key: suggestedCredentialKey,
    ...extras,
  };
}

function upsertOAuthCredential(
  avs: AgentVaultStore,
  vault: AgentVaultVault,
  key: string,
  body: Record<string, unknown>,
): AgentVaultOAuthCredential {
  const previous = avs.oauthCredentials.findBy("vault_id", vault.vault_id).find((candidate) => candidate.key === key);
  const data = {
    vault_id: vault.vault_id,
    key,
    authorization_url: String(body.authorization_url ?? previous?.authorization_url ?? ""),
    token_url: String(body.token_url ?? previous?.token_url ?? ""),
    client_id: String(body.client_id ?? previous?.client_id ?? "emulated-client"),
    client_secret: String(body.client_secret ?? previous?.client_secret ?? ""),
    scopes: String(body.scopes ?? previous?.scopes ?? ""),
    scope_separator: String(body.scope_separator ?? previous?.scope_separator ?? " "),
    disable_pkce: Boolean(body.disable_pkce ?? previous?.disable_pkce ?? false),
    token_auth_method: String(body.token_auth_method ?? previous?.token_auth_method ?? "client_secret_post"),
    access_token: String(body.access_token ?? previous?.access_token ?? ""),
    refresh_token: String(body.refresh_token ?? previous?.refresh_token ?? ""),
    connected_at: previous?.connected_at ?? null,
    last_refreshed_at: previous?.last_refreshed_at ?? null,
    last_refresh_error: previous?.last_refresh_error ?? null,
  };
  return previous ? avs.oauthCredentials.update(previous.id, data)! : avs.oauthCredentials.insert(data);
}

function upsertCredential(
  avs: AgentVaultStore,
  vaultIdValue: string,
  key: string,
  value: string,
  type: AgentVaultCredential["type"],
): void {
  const existing = avs.credentials.findBy("vault_id", vaultIdValue).find((credential) => credential.key === key);
  if (existing) {
    avs.credentials.update(existing.id, { value, type });
  } else {
    avs.credentials.insert({ vault_id: vaultIdValue, key, value, type });
  }
}

function createProposal(
  avs: AgentVaultStore,
  vault: AgentVaultVault,
  body: Record<string, unknown>,
  actorName: string,
): AgentVaultProposal {
  const nextId = avs.proposals.all().reduce((max, proposal) => Math.max(max, proposal.proposal_id), 0) + 1;
  return avs.proposals.insert({
    proposal_id: nextId,
    vault_id: vault.vault_id,
    vault_name: vault.name,
    status: "pending",
    services_json: JSON.stringify(Array.isArray(body.services) ? body.services : []),
    credentials_json: JSON.stringify(Array.isArray(body.credentials) ? body.credentials : []),
    message: String(body.message ?? ""),
    user_message: String(body.user_message ?? ""),
    approval_token: generateId("av_prop"),
    actor_name: actorName,
    resolved_at: null,
  });
}

function filterProposals(c: Context, avs: AgentVaultStore): AgentVaultProposal[] {
  const vaultName = c.req.query("vault");
  const status = c.req.query("status");
  return avs.proposals
    .all()
    .filter((proposal) => !vaultName || proposal.vault_name === vaultName)
    .filter((proposal) => !status || proposal.status === status)
    .sort((a, b) => b.proposal_id - a.proposal_id);
}

function proposalByParam(c: Context, avs: AgentVaultStore): AgentVaultProposal | undefined {
  const id = Number(c.req.param("id"));
  return avs.proposals.all().find((proposal) => proposal.proposal_id === id);
}

function formatProposal(proposal: AgentVaultProposal) {
  return {
    id: proposal.proposal_id,
    status: proposal.status,
    vault: proposal.vault_name,
    services_json: proposal.services_json,
    credentials_json: proposal.credentials_json,
    message: proposal.message,
    user_message: proposal.user_message,
    created_at: proposal.created_at,
    resolved_at: proposal.resolved_at ?? undefined,
    agent_name: proposal.actor_name,
  };
}

function applyProposal(avs: AgentVaultStore, proposal: AgentVaultProposal, body: Record<string, unknown>): void {
  const vault = avs.vaults.findOneBy("vault_id", proposal.vault_id);
  if (!vault) return;

  const credentialValues =
    body.credentials && typeof body.credentials === "object" && !Array.isArray(body.credentials)
      ? (body.credentials as Record<string, unknown>)
      : {};
  const credentialSlots = JSON.parse(proposal.credentials_json) as Array<Record<string, unknown>>;
  for (const slot of credentialSlots) {
    const key = String(slot.key ?? "");
    if (!key) continue;
    if (slot.action === "delete") {
      const existing = avs.credentials.findBy("vault_id", vault.vault_id).find((credential) => credential.key === key);
      if (existing) avs.credentials.delete(existing.id);
    } else {
      upsertCredential(avs, vault.vault_id, key, String(credentialValues[key] ?? slot.value ?? ""), "static");
    }
  }

  const serviceSlots = JSON.parse(proposal.services_json) as Array<Record<string, unknown>>;
  for (const slot of serviceSlots) {
    const action = String(slot.action ?? "set");
    const ref = String(slot.name ?? slot.host ?? "");
    const existing = avs.services
      .findBy("vault_id", vault.vault_id)
      .find((service) => service.name === ref || service.host === ref);
    if (action === "delete") {
      if (existing) avs.services.delete(existing.id);
      continue;
    }
    const service = normalizeService(slot, vault.vault_id);
    if (validateService(service)) continue;
    if (existing) {
      avs.services.update(existing.id, service);
    } else {
      avs.services.insert(service);
    }
  }
}

function oneDayFromNow(): string {
  return new Date(Date.now() + 86400 * 1000).toISOString();
}
