import { decodeJwt, generateKeyPair, exportPKCS8, exportSPKI, jwtVerify, importSPKI } from "jose";
import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type TokenMap } from "@emulators/core";
import { auth0Plugin, getAuth0Store, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";

let app: Hono;
let store: Store;
let tokenMap: TokenMap;
let webhooks: WebhookDispatcher;

function createTestApp() {
  store = new Store();
  webhooks = new WebhookDispatcher();
  tokenMap = new Map();

  app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  auth0Plugin.register(app as any, store, webhooks, base, tokenMap);
  auth0Plugin.seed?.(store, base);
  seedFromConfig(store, base, {
    connections: [{ name: "Username-Password-Authentication" }],
    users: [
      {
        email: "alice@example.com",
        user_id: "alice",
        password: "Alice1234!",
        email_verified: true,
        given_name: "Alice",
        family_name: "Example",
        app_metadata: { userId: 12345, role: "USER" },
      },
    ],
    oauth_clients: [
      {
        client_id: "m2m-client",
        client_secret: "m2m-secret",
        name: "M2M Client",
        grant_types: ["client_credentials"],
        audience: `${base}/api/v2/`,
      },
      {
        client_id: "app-client",
        client_secret: "app-secret",
        name: "App Client",
        grant_types: ["authorization_code", "refresh_token", "http://auth0.com/oauth/grant-type/password-realm"],
      },
      {
        client_id: "other-client",
        client_secret: "other-secret",
        name: "Other Client",
        grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
      },
    ],
  });
}

async function getManagementToken(): Promise<string> {
  const res = await app.request(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: "m2m-client",
      client_secret: "m2m-secret",
      audience: `${base}/api/v2/`,
    }),
  });
  const body = (await res.json()) as { access_token: string };
  return body.access_token;
}

function mgmtHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

beforeEach(() => {
  createTestApp();
});

describe("OIDC Discovery", () => {
  it("returns openid-configuration", async () => {
    const res = await app.request(`${base}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.issuer).toBe(`${base}/`);
    expect(body.token_endpoint).toBe(`${base}/oauth/token`);
    expect(body.userinfo_endpoint).toBe(`${base}/userinfo`);
    expect(body.jwks_uri).toBe(`${base}/.well-known/jwks.json`);
  });

  it("returns JWKS", async () => {
    const res = await app.request(`${base}/.well-known/jwks.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: Array<{ kid: string; alg: string }> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]!.kid).toBe("emulate-auth0-1");
    expect(body.keys[0]!.alg).toBe("RS256");
  });
});

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

async function authorizeCode(
  options: { verifier?: string; redirectUri?: string; state?: string; nonce?: string } = {},
) {
  const verifier = options.verifier ?? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const redirectUri = options.redirectUri ?? "http://localhost:3000/callback";
  const query = new URLSearchParams({
    response_type: "code",
    client_id: "app-client",
    redirect_uri: redirectUri,
    scope: "openid profile email",
    code_challenge: s256(verifier),
    code_challenge_method: "S256",
    state: options.state ?? "state value&=%",
  });
  if (options.nonce) query.set("nonce", options.nonce);
  const page = await app.request(`${base}/authorize?${query}`);
  const html = await page.text();
  expect(page.status).toBe(200);
  expect(html).toContain('data-testid="auth0-login-form"');
  expect(html).toContain('data-testid="auth0-login-email"');

  const login = await app.request(`${base}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...Object.fromEntries(query),
      email: "alice@example.com",
      password: "Alice1234!",
    }).toString(),
  });
  expect(login.status).toBe(302);
  const location = new URL(login.headers.get("location")!);
  expect(location.searchParams.get("state")).toBe(options.state ?? "state value&=%");
  return { code: location.searchParams.get("code")!, verifier, redirectUri };
}

describe("Authorization code with mandatory PKCE", () => {
  it.each([
    ["unsupported response_type", { response_type: "token" }, "response_type must be code"],
    ["unknown client", { client_id: "unknown-client" }, "Unknown client_id"],
    ["unregistered redirect", { redirect_uri: "http://attacker.example/callback" }, "Invalid redirect_uri"],
  ])("rejects %s without redirecting", async (_name, override, description) => {
    const query = new URLSearchParams({
      response_type: "code",
      client_id: "app-client",
      redirect_uri: "http://localhost:3000/callback",
      code_challenge: "challenge",
      code_challenge_method: "S256",
      ...override,
    });
    const response = await app.request(`${base}/authorize?${query}`);
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.json()).toEqual({ error: "invalid_request", error_description: description });
  });

  it("renders credential refusals as inspectable browser pages without issuing redirects", async () => {
    seedFromConfig(store, base, { now: 1_700_000_000, seed: "credential-refusal" });
    const query = new URLSearchParams({
      response_type: "code",
      client_id: "app-client",
      redirect_uri: "http://localhost:3000/callback",
      code_challenge: "challenge",
      code_challenge_method: "S256",
      email: "alice@example.com",
      password: "wrong-password",
    });
    const response = await app.request(`${base}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: query.toString(),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.text()).toContain("Wrong email or password");

    const auth0 = getAuth0Store(store);
    const user = auth0.users.findOneBy("email", "alice@example.com");
    expect(user).toBeDefined();
    auth0.users.update(user!.id, { blocked: true });
    const blocked = await app.request(`${base}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        ...Object.fromEntries(query),
        email: "alice@example.com",
        password: "Alice1234!",
      }).toString(),
    });
    expect(blocked.status).toBe(200);
    expect(blocked.headers.get("location")).toBeNull();
    expect(await blocked.text()).toContain("user is blocked");
  });

  it("renders the shared login form and exchanges a single-use code for RS256 tokens", async () => {
    seedFromConfig(store, base, { now: 1_700_000_000, seed: "auth-code-test" });
    const { code, verifier, redirectUri } = await authorizeCode({ nonce: "nonce-123" });
    const exchange = () =>
      app.request(`${base}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: "app-client",
          client_secret: "app-secret",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });

    const res = await exchange();
    expect(res.status).toBe(200);
    const tokens = (await res.json()) as { access_token: string; id_token: string };
    const accessClaims = decodeJwt(tokens.access_token);
    expect(accessClaims).toMatchObject({
      iss: `${base}/`,
      sub: expect.stringMatching(/^auth0\|/),
      aud: "app-client",
      iat: 1_700_000_000,
      exp: 1_700_003_600,
    });
    expect(Object.keys(accessClaims).sort()).toEqual(["aud", "exp", "iat", "iss", "sub"]);
    const idClaims = decodeJwt(tokens.id_token);
    expect(idClaims).toMatchObject({ nonce: "nonce-123", email: "alice@example.com", name: "alice@example.com" });
    expect(Object.keys(idClaims).sort()).toEqual(["aud", "email", "exp", "iat", "iss", "name", "nonce", "sub"]);

    const reused = await exchange();
    expect(reused.status).toBe(400);
    expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
  });

  it.each([
    ["plain", "challenge", "code_challenge_method must be S256"],
    ["S256", "", "code_challenge is required"],
  ])("rejects invalid PKCE directly without redirect", async (method, challenge, description) => {
    const query = new URLSearchParams({
      response_type: "code",
      client_id: "app-client",
      redirect_uri: "http://localhost:3000/callback",
      code_challenge_method: method,
    });
    if (challenge) query.set("code_challenge", challenge);
    const res = await app.request(`${base}/authorize?${query}`);
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.json()).toEqual({ error: "invalid_request", error_description: description });
  });

  it("rejects a wrong verifier and redirect URI without consuming the code", async () => {
    const { code, verifier, redirectUri } = await authorizeCode();
    const exchange = (codeVerifier: string, uri: string) =>
      app.request(`${base}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: "app-client",
          client_secret: "app-secret",
          code,
          redirect_uri: uri,
          code_verifier: codeVerifier,
        }),
      });
    expect((await exchange("wrong-verifier", redirectUri)).status).toBe(400);
    expect((await exchange(verifier, "http://localhost:3000/wrong")).status).toBe(400);
    expect((await exchange(verifier, redirectUri)).status).toBe(200);
  });

  it("allows exactly one concurrent exchange", async () => {
    const { code, verifier, redirectUri } = await authorizeCode();
    const exchange = () =>
      app.request(`${base}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: "app-client",
          client_secret: "app-secret",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });
    const statuses = (await Promise.all([exchange(), exchange()])).map((response) => response.status).sort();
    expect(statuses).toEqual([200, 400]);
  });

  it("returns expired_token under an injected clock", async () => {
    seedFromConfig(store, base, { now: 100, seed: "expiry", authorization_code_ttl_seconds: 1 });
    const { code, verifier, redirectUri } = await authorizeCode();
    seedFromConfig(store, base, { now: 101, seed: "expiry", authorization_code_ttl_seconds: 1 });
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: "app-client",
        client_secret: "app-secret",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "expired_token" });
  });
});

async function startDeviceGrant(seed = "device-test", now = 1_700_000_000) {
  seedFromConfig(store, base, { now, seed });
  const res = await app.request(`${base}/oauth/device/code`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: "app-client", scope: "openid profile email" }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { device_code: string; user_code: string; verification_uri_complete: string };
}

function pollDevice(deviceCode: string) {
  return app.request(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: "app-client",
      client_secret: "app-secret",
      device_code: deviceCode,
    }),
  });
}

describe("Device authorization", () => {
  it("rejects an unknown client before issuing a device grant", async () => {
    const response = await app.request(`${base}/oauth/device/code`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: "unknown-client", scope: "openid" }).toString(),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request", error_description: "Unknown client_id" });
  });

  it("rejects a device grant polled by another valid client without consuming it", async () => {
    const grant = await startDeviceGrant("wrong-device-client");
    const wrongClient = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        client_id: "other-client",
        client_secret: "other-secret",
        device_code: grant.device_code,
      }),
    });
    expect(wrongClient.status).toBe(400);
    expect(await wrongClient.json()).toEqual({ error: "invalid_grant", error_description: "Wrong client_id." });

    const ownerPoll = await pollDevice(grant.device_code);
    expect(ownerPoll.status).toBe(400);
    expect(await ownerPoll.json()).toMatchObject({ error: "authorization_pending" });
  });

  it("renders unknown-code and credential refusals as inspectable browser pages", async () => {
    const unknown = await app.request(`${base}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ user_code: "UNKNOWN", decision: "approve" }).toString(),
    });
    expect(unknown.status).toBe(200);
    expect(await unknown.text()).toContain("Unknown device code");

    const grant = await startDeviceGrant("credential-refusal");
    const wrongCredentials = await app.request(`${base}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        user_code: grant.user_code,
        email: "alice@example.com",
        password: "wrong-password",
        decision: "approve",
      }).toString(),
    });
    expect(wrongCredentials.status).toBe(200);
    expect(await wrongCredentials.text()).toContain("Wrong email or password");
    expect((await pollDevice(grant.device_code)).status).toBe(400);

    const expiredGrant = await startDeviceGrant("expired-form", 100);
    seedFromConfig(store, base, { now: 700, seed: "expired-form" });
    const expired = await app.request(`${base}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        user_code: expiredGrant.user_code,
        email: "alice@example.com",
        password: "Alice1234!",
        decision: "approve",
      }).toString(),
    });
    expect(expired.status).toBe(200);
    expect(expired.headers.get("location")).toBeNull();
    expect(await expired.text()).toContain("Expired device code");
  });

  it("renders stable hooks, reports pending, approves, and exchanges once", async () => {
    const grant = await startDeviceGrant();
    const pending = await pollDevice(grant.device_code);
    expect(pending.status).toBe(400);
    expect(await pending.json()).toMatchObject({ error: "authorization_pending" });

    const page = await app.request(grant.verification_uri_complete);
    const html = await page.text();
    expect(html).toContain('data-testid="auth0-device-form"');
    expect(html).toContain('data-testid="auth0-device-approve"');
    expect(html).toContain('data-testid="auth0-device-deny"');

    const approval = await app.request(`${base}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        user_code: grant.user_code,
        email: "alice@example.com",
        password: "Alice1234!",
        decision: "approve",
      }).toString(),
    });
    expect(approval.status).toBe(200);
    expect((await pollDevice(grant.device_code)).status).toBe(200);
    expect((await pollDevice(grant.device_code)).status).toBe(400);
  });

  it("returns access_denied after denial and invalid_grant for fabricated codes", async () => {
    const grant = await startDeviceGrant("denial");
    await app.request(`${base}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ user_code: grant.user_code, decision: "deny" }).toString(),
    });
    const denied = await pollDevice(grant.device_code);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: "access_denied" });
    const fabricated = await pollDevice("fabricated");
    expect(fabricated.status).toBe(400);
    expect(await fabricated.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("returns expired_token under an injected clock", async () => {
    const grant = await startDeviceGrant("device-expiry", 100);
    seedFromConfig(store, base, { now: 700, seed: "device-expiry" });
    const expired = await pollDevice(grant.device_code);
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ error: "expired_token" });
  });
});

describe("OAuth /oauth/token", () => {
  it("client_credentials returns access token", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: "m2m-client",
        client_secret: "m2m-secret",
        audience: `${base}/api/v2/`,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(86400);
  });

  it("password-realm returns tokens and id_token", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email offline_access",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.id_token).toBeTruthy();

    const claims = decodeJwt(body.id_token as string);
    expect(claims.email).toBe("alice@example.com");
    expect(claims.given_name).toBe("Alice");
  });

  it("password-realm rejects wrong password", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "WrongPassword1!",
        realm: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; error_description: string };
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toBe("Wrong email or password.");
  });

  it("password-realm rejects blocked user", async () => {
    const auth0 = getAuth0Store(store);
    const user = auth0.users.findOneBy("email", "alice@example.com");
    if (user) auth0.users.update(user.id, { blocked: true });

    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; error_description: string };
    expect(body.error).toBe("unauthorized");
    expect(body.error_description).toBe("user is blocked");
  });

  it("refresh_token returns new tokens", async () => {
    // First get tokens via password-realm
    const loginRes = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email offline_access",
      }),
    });
    const loginBody = (await loginRes.json()) as { refresh_token: string };

    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        client_id: "app-client",
        client_secret: "app-secret",
        refresh_token: loginBody.refresh_token,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.access_token).not.toBe(loginBody.refresh_token);
  });

  it("rejects unknown client", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: "nonexistent",
        client_secret: "nope",
      }),
    });
    expect(res.status).toBe(401);
  });
});

describe("Management API - Users", () => {
  it("creates a user", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "newuser@example.com",
        password: "NewUser1234!",
        connection: "Username-Password-Authentication",
        app_metadata: { userId: 99999, role: "USER" },
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("newuser@example.com");
    expect(body.user_id).toMatch(/^auth0\|/);
    expect((body.app_metadata as Record<string, unknown>).userId).toBe(99999);
  });

  it("rejects duplicate user with exact Auth0 error message", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "alice@example.com",
        password: "Alice1234!",
        connection: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(409);
    const body = (await res.json()) as { statusCode: number; error: string; message: string; errorCode: string };
    expect(body.statusCode).toBe(409);
    expect(body.error).toBe("Conflict");
    expect(body.message).toBe("The user already exists.");
  });

  it("rejects invalid email with exact Auth0 error message", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "not-an-email",
        password: "Test1234!",
        connection: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { statusCode: number; error: string; message: string; errorCode: string };
    expect(body.statusCode).toBe(400);
    expect(body.message).toContain("Object didn't pass validation for format email");
  });

  it("rejects weak password with PasswordStrengthError", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "weak@example.com",
        password: "weak",
        connection: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { statusCode: number; error: string; message: string; errorCode: string };
    expect(body.statusCode).toBe(400);
    expect(body.message).toContain("PasswordStrengthError");
  });

  it("gets user by ID", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    const res = await app.request(`${base}/api/v2/users/${encodeURIComponent(alice.user_id)}`, {
      headers: mgmtHeaders(token),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("alice@example.com");
  });

  it("lists users by email", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users-by-email?email=alice@example.com`, {
      headers: mgmtHeaders(token),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Array<Record<string, unknown>>;
    expect(body).toHaveLength(1);
    expect(body[0]!.email).toBe("alice@example.com");
  });

  it("updates user app_metadata", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    const res = await app.request(`${base}/api/v2/users/${encodeURIComponent(alice.user_id)}`, {
      method: "PATCH",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        app_metadata: { userId: 12345, role: "USER", securitiesLimit: 100 },
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const metadata = body.app_metadata as Record<string, unknown>;
    expect(metadata.securitiesLimit).toBe(100);
    expect(metadata.userId).toBe(12345);
  });

  it("updates email_verified", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    const res = await app.request(`${base}/api/v2/users/${encodeURIComponent(alice.user_id)}`, {
      method: "PATCH",
      headers: mgmtHeaders(token),
      body: JSON.stringify({ email_verified: true }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email_verified).toBe(true);
  });

  it("rejects unauthenticated management calls", async () => {
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "unauth@example.com",
        password: "Test1234!",
        connection: "Username-Password-Authentication",
      }),
    });
    expect(res.status).toBe(401);
  });
});

describe("Management API - Tickets", () => {
  it("creates email verification ticket", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    const res = await app.request(`${base}/api/v2/tickets/email-verification`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        user_id: alice.user_id,
        result_url: "https://example.com/email-verification-success/",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ticket: string };
    expect(body.ticket).toContain("/tickets/email-verification?ticket=");
  });
});

describe("Userinfo", () => {
  it("returns user profile for authenticated user", async () => {
    // Login first
    const loginRes = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email",
      }),
    });
    const loginBody = (await loginRes.json()) as { access_token: string };

    const res = await app.request(`${base}/userinfo`, {
      headers: { Authorization: `Bearer ${loginBody.access_token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("alice@example.com");
    expect(body.given_name).toBe("Alice");
    expect(body.family_name).toBe("Example");
  });
});

describe("Token Revocation", () => {
  it("revokes a token", async () => {
    const loginRes = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
      }),
    });
    const loginBody = (await loginRes.json()) as { refresh_token: string };

    const res = await app.request(`${base}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: loginBody.refresh_token }),
    });
    expect(res.status).toBe(200);
  });
});

// These tests validate that error response formats exactly match Auth0's
// actual API responses, ensuring SDK error handling works unchanged.
describe("Auth0 error format fidelity", () => {
  it("Authentication API errors use { error, error_description } format", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "WrongPassword1!",
        realm: "Username-Password-Authentication",
      }),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("error_description");
    expect(body).toHaveProperty("error");
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toBe("Wrong email or password.");
    // Should NOT have Management API fields
    expect(body).not.toHaveProperty("statusCode");
    expect(body).not.toHaveProperty("message");
  });

  it("Management API errors use { statusCode, error, message, errorCode } format", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "alice@example.com",
        password: "Alice1234!",
        connection: "Username-Password-Authentication",
      }),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("statusCode");
    expect(body).toHaveProperty("error");
    expect(body).toHaveProperty("message");
    expect(body).toHaveProperty("errorCode");
    expect(body.statusCode).toBe(409);
    expect(body.message).toBe("The user already exists.");
  });

  it("refresh_token error returns exact Auth0 error description", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        client_id: "app-client",
        client_secret: "app-secret",
        refresh_token: "invalid_token_value",
      }),
    });
    const body = (await res.json()) as { error: string; error_description: string };
    expect(body.error_description).toBe("Unknown or invalid refresh token.");
    expect(body.error).toBe("invalid_grant");
  });

  it("user not found returns exact Auth0 error description", async () => {
    const token = await getManagementToken();
    const res = await app.request(`${base}/api/v2/users/${encodeURIComponent("auth0|999999")}`, {
      headers: mgmtHeaders(token),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { message: string };
    expect(body.message).toBe("The user does not exist.");
  });
});

describe("Log Events (webhook dispatch)", () => {
  beforeEach(() => {
    // Register a catch-all subscriber so dispatches are recorded as deliveries
    webhooks.register({
      url: "http://localhost:9999/test-hook",
      events: ["*"],
      active: true,
      owner: "auth0",
    });
  });

  it("dispatches 'ss' event on successful user creation", async () => {
    const token = await getManagementToken();
    const email = `logtest-${Date.now()}@example.com`;

    await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email,
        password: "SecurePass1!",
        connection: "Username-Password-Authentication",
      }),
    });

    const deliveries = webhooks.getDeliveries();
    const ssDelivery = deliveries.find((d) => d.event === "ss");
    expect(ssDelivery).toBeDefined();
    const payload = ssDelivery!.payload as Record<string, unknown>;
    expect(payload.type).toBe("ss");
    expect(payload.user_name).toBe(email);
    expect(payload.user_id).toMatch(/^auth0\|/);
    expect(payload.log_id).toBeTruthy();
    expect(payload.date).toBeTruthy();
    expect(payload.connection).toBe("Username-Password-Authentication");
    expect(payload.strategy).toBe("auth0");
    expect(payload.strategy_type).toBe("database");
  });

  it("dispatches 'fs' event on failed signup (duplicate)", async () => {
    const token = await getManagementToken();

    await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "alice@example.com",
        password: "Alice1234!",
        connection: "Username-Password-Authentication",
      }),
    });

    const deliveries = webhooks.getDeliveries();
    const fsDelivery = deliveries.find((d) => d.event === "fs");
    expect(fsDelivery).toBeDefined();
    const payload = fsDelivery!.payload as Record<string, unknown>;
    expect(payload.type).toBe("fs");
    expect(payload.user_name).toBe("alice@example.com");
  });

  it("dispatches 'scp' event on password change", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    await app.request(`${base}/api/v2/users/${encodeURIComponent(alice.user_id)}`, {
      method: "PATCH",
      headers: mgmtHeaders(token),
      body: JSON.stringify({ password: "NewPassword1!" }),
    });

    const deliveries = webhooks.getDeliveries();
    const scpDelivery = deliveries.find((d) => d.event === "scp");
    expect(scpDelivery).toBeDefined();
    const payload = scpDelivery!.payload as Record<string, unknown>;
    expect(payload.type).toBe("scp");
    expect(payload.user_id).toBe(alice.user_id);
    expect(payload.user_name).toBe("alice@example.com");
  });

  it("does not dispatch 'scp' on non-password PATCH", async () => {
    const token = await getManagementToken();
    const auth0 = getAuth0Store(store);
    const alice = auth0.users.findOneBy("email", "alice@example.com")!;

    await app.request(`${base}/api/v2/users/${encodeURIComponent(alice.user_id)}`, {
      method: "PATCH",
      headers: mgmtHeaders(token),
      body: JSON.stringify({ email_verified: true }),
    });

    const deliveries = webhooks.getDeliveries();
    const scpDelivery = deliveries.find((d) => d.event === "scp");
    expect(scpDelivery).toBeUndefined();
  });
});

describe("Additional coverage", () => {
  it("password-realm without offline_access does not return refresh_token", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
    expect(body.id_token).toBeTruthy();
    expect(body).not.toHaveProperty("refresh_token");
  });

  it("plain password grant type also works", async () => {
    const res = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "password",
        client_id: "app-client",
        client_secret: "app-secret",
        username: "alice@example.com",
        password: "Alice1234!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
  });

  it("client_credentials token is rejected by /userinfo", async () => {
    const tokenRes = await app.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: "m2m-client",
        client_secret: "m2m-secret",
        audience: `${base}/api/v2/`,
      }),
    });
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const res = await app.request(`${base}/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    expect(res.status).toBe(401);
  });

  it("email verification ticket consumption marks user verified and dispatches sv", async () => {
    webhooks.register({
      url: "http://localhost:9999/test-hook",
      events: ["*"],
      active: true,
      owner: "auth0",
    });

    const token = await getManagementToken();

    // Create an unverified user
    const createRes = await app.request(`${base}/api/v2/users`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        email: "verify-test@example.com",
        password: "Verify1234!",
        connection: "Username-Password-Authentication",
        verify_email: true,
      }),
    });
    const created = (await createRes.json()) as Record<string, unknown>;
    expect(created.email_verified).toBe(false);

    // Create ticket
    const ticketRes = await app.request(`${base}/api/v2/tickets/email-verification`, {
      method: "POST",
      headers: mgmtHeaders(token),
      body: JSON.stringify({
        user_id: created.user_id,
        result_url: "https://example.com/verified",
      }),
    });
    const { ticket } = (await ticketRes.json()) as { ticket: string };

    // Consume ticket
    const ticketPath = ticket.replace(base, "");
    const consumeRes = await app.request(`${base}${ticketPath}`);
    expect(consumeRes.status).toBe(302);

    // Verify user is now email_verified
    const userRes = await app.request(`${base}/api/v2/users/${encodeURIComponent(created.user_id as string)}`, {
      headers: mgmtHeaders(token),
    });
    const user = (await userRes.json()) as Record<string, unknown>;
    expect(user.email_verified).toBe(true);

    // Verify sv event dispatched
    const deliveries = webhooks.getDeliveries();
    const svDelivery = deliveries.find((d) => d.event === "sv");
    expect(svDelivery).toBeDefined();
    const payload = svDelivery!.payload as Record<string, unknown>;
    expect(payload.type).toBe("sv");
    expect(payload.user_name).toBe("verify-test@example.com");
  });

  it("OIDC discovery advertises authorization code, PKCE, and device authorization", async () => {
    const res = await app.request(`${base}/.well-known/openid-configuration`);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.authorization_endpoint).toBe(`${base}/authorize`);
    expect(body.device_authorization_endpoint).toBe(`${base}/oauth/device/code`);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
  });
});

describe("Deterministic OAuth state", () => {
  it("replays generated codes after store reset and reseed", async () => {
    seedFromConfig(store, base, { now: 1_700_000_000, seed: "reset-seed" });
    const first = await authorizeCode({ state: "reset" });

    createTestApp();
    seedFromConfig(store, base, { now: 1_700_000_000, seed: "reset-seed" });
    const second = await authorizeCode({ state: "reset" });
    expect(second.code).toBe(first.code);
  });

  it("clears outstanding grants when the store resets", async () => {
    seedFromConfig(store, base, {
      now: 1_700_000_000,
      seed: "clear-grants",
      users: [{ email: "alice@example.com", password: "Alice1234!", user_id: "alice" }],
      oauth_clients: [
        {
          client_id: "app-client",
          client_secret: "app-secret",
          redirect_uris: ["http://localhost:3000/callback"],
        },
      ],
    });
    const grant = await startDeviceGrant("clear-grants");
    store.reset();
    auth0Plugin.seed?.(store, base);
    seedFromConfig(store, base, {
      now: 1_700_000_000,
      seed: "clear-grants",
      users: [{ email: "alice@example.com", password: "Alice1234!", user_id: "alice" }],
      oauth_clients: [
        {
          client_id: "app-client",
          client_secret: "app-secret",
          redirect_uris: ["http://localhost:3000/callback"],
        },
      ],
    });
    const poll = await pollDevice(grant.device_code);
    expect(poll.status).toBe(400);
    expect(await poll.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("issues byte-identical tokens with the same key, clock, seed, and inputs", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    const privatePem = await exportPKCS8(privateKey);
    const publicPem = await exportSPKI(publicKey);
    const run = async () => {
      createTestApp();
      seedFromConfig(store, base, {
        now: 1_700_000_000,
        seed: "token-replay",
        signing_key: { private_key_pem: privatePem, public_key_pem: publicPem, kid: "fixed-test-kid" },
      });
      const { code, verifier, redirectUri } = await authorizeCode({ nonce: "fixed-nonce", state: "fixed-state" });
      const res = await app.request(`${base}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: "app-client",
          client_secret: "app-secret",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });
      expect(res.status).toBe(200);
      return (await res.json()) as { access_token: string; id_token: string };
    };

    const first = await run();
    const second = await run();
    expect(second).toEqual(first);
  });
});

describe("Deterministic signing key", () => {
  let configKeyApp: Hono;
  let configKeyStore: Store;
  let configKeyTokenMap: TokenMap;
  let testPublicPem: string;

  beforeEach(async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    const privatePem = await exportPKCS8(privateKey);
    testPublicPem = await exportSPKI(publicKey);

    configKeyStore = new Store();
    const wh = new WebhookDispatcher();
    configKeyTokenMap = new Map();

    configKeyApp = new Hono();
    configKeyApp.use("*", authMiddleware(configKeyTokenMap));
    auth0Plugin.register(configKeyApp as any, configKeyStore, wh, base, configKeyTokenMap);
    auth0Plugin.seed?.(configKeyStore, base);
    seedFromConfig(configKeyStore, base, {
      connections: [{ name: "Username-Password-Authentication" }],
      users: [{ email: "key-test@example.com", password: "KeyTest1!" }],
      oauth_clients: [
        {
          client_id: "ka",
          client_secret: "kas",
          grant_types: ["http://auth0.com/oauth/grant-type/password-realm"],
        },
      ],
      signing_key: {
        private_key_pem: privatePem,
        public_key_pem: testPublicPem,
        kid: "custom-kid-1",
      },
    });
  });

  it("JWKS serves the config-provided key with custom kid", async () => {
    const res = await configKeyApp.request(`${base}/.well-known/jwks.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: Array<{ kid: string; alg: string }> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]!.kid).toBe("custom-kid-1");
  });

  it("tokens are verifiable with the provided public key", async () => {
    const loginRes = await configKeyApp.request(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: "ka",
        client_secret: "kas",
        username: "key-test@example.com",
        password: "KeyTest1!",
        realm: "Username-Password-Authentication",
        scope: "openid profile email",
      }),
    });
    const { id_token } = (await loginRes.json()) as { id_token: string };
    expect(id_token).toBeTruthy();

    // Verify the token with the known public key
    const pubKey = await importSPKI(testPublicPem, "RS256");
    const { payload } = await jwtVerify(id_token, pubKey);
    expect(payload.email).toBe("key-test@example.com");
  });

  it("/_emulate/public-key.pem returns valid PEM matching config", async () => {
    const res = await configKeyApp.request(`${base}/_emulate/public-key.pem`);
    expect(res.status).toBe(200);
    const pem = await res.text();
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    expect(pem).toContain("-----END PUBLIC KEY-----");
    // Should be the same key we provided
    expect(pem.trim()).toBe(testPublicPem.trim());
  });

  it("default (no signing_key) still generates a random key", async () => {
    // The main test app uses default keys
    const res = await app.request(`${base}/.well-known/jwks.json`);
    const body = (await res.json()) as { keys: Array<{ kid: string }> };
    expect(body.keys[0]!.kid).toBe("emulate-auth0-1");
  });

  it("/_emulate/public-key.pem works with auto-generated key", async () => {
    const res = await app.request(`${base}/_emulate/public-key.pem`);
    expect(res.status).toBe(200);
    const pem = await res.text();
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
  });

  it("kid defaults to emulate-auth0-1 when not specified in config", async () => {
    const noKidStore = new Store();
    const wh = new WebhookDispatcher();
    const tm: TokenMap = new Map();
    const noKidApp = new Hono();
    noKidApp.use("*", authMiddleware(tm));
    auth0Plugin.register(noKidApp as any, noKidStore, wh, base, tm);
    auth0Plugin.seed?.(noKidStore, base);

    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    seedFromConfig(noKidStore, base, {
      signing_key: {
        private_key_pem: await exportPKCS8(privateKey),
        public_key_pem: await exportSPKI(publicKey),
      },
    });

    const res = await noKidApp.request(`${base}/.well-known/jwks.json`);
    const body = (await res.json()) as { keys: Array<{ kid: string }> };
    expect(body.keys[0]!.kid).toBe("emulate-auth0-1");
  });

  it("invalid PEM throws a clear error on first request", async () => {
    const badStore = new Store();
    const wh = new WebhookDispatcher();
    const tm: TokenMap = new Map();
    const badApp = new Hono();
    badApp.use("*", authMiddleware(tm));
    auth0Plugin.register(badApp as any, badStore, wh, base, tm);
    auth0Plugin.seed?.(badStore, base);
    seedFromConfig(badStore, base, {
      signing_key: {
        private_key_pem: "not-a-valid-pem",
        public_key_pem: "also-not-valid",
      },
    });

    const res = await badApp.request(`${base}/.well-known/jwks.json`);
    expect(res.status).toBe(500);
  });

  it("throws when only private_key_pem is provided", () => {
    const s = new Store();
    expect(() =>
      seedFromConfig(s, base, {
        signing_key: {
          private_key_pem: "something",
          public_key_pem: "",
        },
      }),
    ).toThrow("signing_key requires both private_key_pem and public_key_pem");
  });

  it("throws when only public_key_pem is provided", () => {
    const s = new Store();
    expect(() =>
      seedFromConfig(s, base, {
        signing_key: {
          private_key_pem: "",
          public_key_pem: "something",
        },
      }),
    ).toThrow("signing_key requires both private_key_pem and public_key_pem");
  });
});
