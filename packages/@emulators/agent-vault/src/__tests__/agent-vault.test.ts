import { beforeEach, describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type TokenMap } from "@emulators/core";
import { agentVaultPlugin, getAgentVaultStore, seedFromConfig } from "../index.js";

const base = "http://localhost:4400";

function createTestApp() {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();
  tokenMap.set("av_agt_test", { login: "default-agent", id: 1, scopes: [] });

  const app = new Hono();
  app.use("*", authMiddleware(tokenMap, undefined, { login: "owner@example.com", id: 1, scopes: [] }));
  agentVaultPlugin.register(app as any, store, webhooks, base, tokenMap);
  agentVaultPlugin.seed?.(store, base);

  return { app, store };
}

function headers(token = "av_agt_test") {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

describe("Agent Vault emulator", () => {
  let app: Hono;
  let store: Store;

  beforeEach(() => {
    const setup = createTestApp();
    app = setup.app;
    store = setup.store;
  });

  it("seeds default vault credentials and services", async () => {
    const vaultsRes = await app.request(`${base}/v1/vaults`, { headers: headers() });
    expect(vaultsRes.status).toBe(200);
    const vaults = (await vaultsRes.json()) as any;
    expect(vaults.vaults[0].name).toBe("default");

    const credentialsRes = await app.request(`${base}/v1/credentials?vault=default&reveal=true&key=GITHUB_PAT`, {
      headers: headers(),
    });
    expect(credentialsRes.status).toBe(200);
    const credentials = (await credentialsRes.json()) as any;
    expect(credentials.keys).toEqual(["GITHUB_PAT"]);
    expect(credentials.credentials[0].value).toBe("ghp_emulated");

    const servicesRes = await app.request(`${base}/v1/vaults/default/services`, { headers: headers() });
    expect(servicesRes.status).toBe(200);
    const services = (await servicesRes.json()) as any;
    expect(services.services.map((service: any) => service.name)).toContain("github");
  });

  it("supports vault, credential, and service management", async () => {
    const createVault = await app.request(`${base}/v1/vaults`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ name: "my-project" }),
    });
    expect(createVault.status).toBe(201);

    const setCredentials = await app.request(`${base}/v1/credentials`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        vault: "my-project",
        credentials: { STRIPE_KEY: "sk_test_123" },
      }),
    });
    expect(setCredentials.status).toBe(200);
    expect(await setCredentials.json()).toEqual({ set: ["STRIPE_KEY"] });

    const setServices = await app.request(`${base}/v1/vaults/my-project/services`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        services: [{ name: "stripe", host: "api.stripe.com", auth: { type: "bearer", token: "STRIPE_KEY" } }],
      }),
    });
    expect(setServices.status).toBe(200);
    const setServicesBody = (await setServices.json()) as any;
    expect(setServicesBody.upserted).toEqual(["stripe"]);
    expect(setServicesBody.services_count).toBe(1);

    const usage = await app.request(`${base}/v1/vaults/my-project/services/credential-usage?key=STRIPE_KEY`, {
      headers: headers(),
    });
    expect(usage.status).toBe(200);
    expect(await usage.json()).toEqual({ services: [{ name: "stripe", host: "api.stripe.com" }] });

    const remove = await app.request(`${base}/v1/vaults/my-project/services/stripe`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(remove.status).toBe(200);
    const removeBody = (await remove.json()) as any;
    expect(removeBody.removed).toBe("stripe");
    expect(removeBody.services_count).toBe(0);
  });

  it("mints scoped sessions and exposes CA metadata", async () => {
    const sessionRes = await app.request(`${base}/v1/sessions`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ vault: "default", ttl_seconds: 3600, label: "sandbox" }),
    });
    expect(sessionRes.status).toBe(200);
    const session = (await sessionRes.json()) as any;
    expect(session.token).toMatch(/^av_sess_/);
    expect(session.av_addr).toBe(base);

    const caRes = await app.request(`${base}/v1/mitm/ca.pem`, { headers: headers() });
    expect(caRes.status).toBe(200);
    expect(caRes.headers.get("X-MITM-Port")).toBe("14322");
    expect(await caRes.text()).toContain("BEGIN CERTIFICATE");

    const sessionsRes = await app.request(`${base}/v1/sessions?vault=default`, { headers: headers() });
    expect(sessionsRes.status).toBe(200);
    const sessions = (await sessionsRes.json()) as any;
    expect(sessions.sessions[0].label).toBe("sandbox");
  });

  it("supports seeded agents and request logs", async () => {
    seedFromConfig(store, base, {
      agents: [
        {
          name: "build-agent",
          token: "av_agt_build",
          role: "member",
          vaults: [{ vault_name: "default", vault_role: "admin" }],
        },
      ],
      logs: [
        {
          vault: "default",
          method: "POST",
          host: "api.github.com",
          path: "/repos/acme/app/issues",
          matched_service: "github",
          status: 201,
        },
      ],
    });

    const agentsRes = await app.request(`${base}/v1/agents`, { headers: headers() });
    expect(agentsRes.status).toBe(200);
    const agents = (await agentsRes.json()) as any;
    expect(agents.agents.map((agent: any) => agent.name)).toContain("build-agent");

    const logsRes = await app.request(`${base}/v1/vaults/default/logs`, { headers: headers() });
    expect(logsRes.status).toBe(200);
    const logs = (await logsRes.json()) as any;
    expect(logs.logs[0]).toMatchObject({
      method: "POST",
      host: "api.github.com",
      matched_service: "github",
      status: 201,
    });
  });

  it("supports web management auth, users, settings, and service catalog endpoints", async () => {
    const me = await app.request(`${base}/v1/auth/me`, { headers: headers() });
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({ type: "user", email: "owner@example.com", is_owner: true });

    const users = await app.request(`${base}/v1/users`, { headers: headers() });
    expect(users.status).toBe(200);
    const usersBody = (await users.json()) as any;
    expect(usersBody.users.map((user: any) => user.email)).toContain("owner@example.com");

    const invite = await app.request(`${base}/v1/users/invites`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        email: "dev@example.com",
        role: "member",
        vaults: [{ vault_name: "default", vault_role: "admin" }],
      }),
    });
    expect(invite.status).toBe(201);
    const inviteBody = (await invite.json()) as any;
    expect(inviteBody.token).toMatch(/^av_inv_/);

    const accept = await app.request(`${base}/v1/users/invites/${encodeURIComponent(inviteBody.token)}/accept`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ password: "password123" }),
    });
    expect(accept.status).toBe(200);

    const vaultUsers = await app.request(`${base}/v1/vaults/default/users`, { headers: headers() });
    expect(vaultUsers.status).toBe(200);
    const vaultUsersBody = (await vaultUsers.json()) as any;
    expect(vaultUsersBody.users.map((user: any) => user.email)).toContain("dev@example.com");

    const settings = await app.request(`${base}/v1/admin/settings`, { headers: headers() });
    expect(settings.status).toBe(200);
    expect(await settings.json()).toMatchObject({ invite_only: false, smtp_configured: false });

    const catalog = await app.request(`${base}/v1/service-catalog`);
    expect(catalog.status).toBe(200);
    const catalogBody = (await catalog.json()) as any;
    expect(catalogBody.services.map((service: any) => service.id)).toContain("stripe");
  });

  it("supports OAuth credential helpers and proposals", async () => {
    const connect = await app.request(`${base}/v1/credentials/oauth/connect`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        vault: "default",
        key: "SLACK_TOKEN",
        authorization_url: "https://slack.com/oauth/v2/authorize",
        token_url: "https://slack.com/api/oauth.v2.access",
        client_id: "client",
        scopes: "chat:write",
      }),
    });
    expect(connect.status).toBe(200);
    const connectBody = (await connect.json()) as any;
    expect(connectBody.authorization_url).toContain("state=");

    const tokens = await app.request(`${base}/v1/credentials/oauth/tokens`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        vault: "default",
        key: "SLACK_TOKEN",
        access_token: "xoxb-emulated",
        refresh_token: "refresh",
      }),
    });
    expect(tokens.status).toBe(200);

    const status = await app.request(`${base}/v1/credentials/oauth/status?vault=default&key=SLACK_TOKEN`, {
      headers: headers(),
    });
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ connected: true, key: "SLACK_TOKEN" });

    const proposal = await app.request(`${base}/v1/proposals`, {
      method: "POST",
      headers: { ...headers(), "x-vault": "default" },
      body: JSON.stringify({
        services: [{ action: "set", name: "slack", host: "slack.com", auth: { type: "bearer", token: "SLACK_TOKEN" } }],
        credentials: [],
        message: "Add Slack access",
      }),
    });
    expect(proposal.status).toBe(201);
    const proposalBody = (await proposal.json()) as any;
    expect(proposalBody.id).toBe(1);

    const approve = await app.request(`${base}/v1/admin/proposals/1/approve`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ vault: "default" }),
    });
    expect(approve.status).toBe(200);

    const services = await app.request(`${base}/v1/vaults/default/services`, { headers: headers() });
    const servicesBody = (await services.json()) as any;
    expect(servicesBody.services.map((service: any) => service.name)).toContain("slack");
  });

  it("renders the inspector", async () => {
    const res = await app.request(`${base}/?tab=services`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Agent Vault Inspector");
  });

  it("resets to seeded state", () => {
    const avs = getAgentVaultStore(store);
    expect(avs.vaults.findOneBy("name", "default")).toBeDefined();
    store.reset();
    agentVaultPlugin.seed?.(store, base);
    expect(getAgentVaultStore(store).vaults.findOneBy("name", "default")).toBeDefined();
  });
});
