import {
  SignJWT,
  exportJWK,
  exportSPKI,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  type CryptoKey as JoseCryptoKey,
} from "jose";
import { createHash } from "node:crypto";
import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import {
  debug,
  escapeAttr,
  escapeHtml,
  renderCardPage,
  renderErrorPage,
  renderUserButton,
} from "@emulators/core";
import type { Auth0User } from "../entities.js";
import { verifyPassword } from "../helpers.js";
import { AUTH0_ERRORS, authenticationApiError } from "../route-helpers.js";
import { getAuth0Store } from "../store.js";
import {
  auth0Lifetime,
  auth0Now,
  generateAuth0Material,
  getAuthorizationCodes,
  getDeviceCodes,
} from "../oauth-state.js";

const DEFAULT_KID = "emulate-auth0-1";

type ResolvedKeyPair = {
  privateKey: JoseCryptoKey;
  publicKey: JoseCryptoKey;
  kid: string;
};

export type SigningKeyConfig = {
  private_key_pem: string;
  public_key_pem: string;
  kid: string;
};

// Cache the Promise (not the resolved value) to prevent race conditions when
// concurrent requests both trigger key resolution before the first completes.
function getSigningKeyPair(store: Store): Promise<ResolvedKeyPair> {
  const cached = store.getData<Promise<ResolvedKeyPair>>("auth0.signing.pending");
  if (cached) return cached;

  const pending = resolveSigningKeyPair(store);
  store.setData("auth0.signing.pending", pending);
  return pending;
}

async function resolveSigningKeyPair(store: Store): Promise<ResolvedKeyPair> {
  const config = store.getData<SigningKeyConfig>("auth0.signing.config");

  if (config) {
    try {
      const privateKey = await importPKCS8(config.private_key_pem, "RS256");
      const publicKey = await importSPKI(config.public_key_pem, "RS256");
      return { privateKey, publicKey, kid: config.kid };
    } catch (e) {
      throw new Error(`Invalid signing_key PEM: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const { privateKey, publicKey } = await generateKeyPair("RS256");
  return { privateKey, publicKey, kid: DEFAULT_KID };
}

type StoredAccessToken = {
  clientId: string;
  scope: string;
  issuedAt: number;
  expiresAt: number;
  userAuth0Id: string | null;
  audience: string;
};

type StoredRefreshToken = {
  clientId: string;
  scope: string;
  userAuth0Id: string;
  audience: string;
};

function getAccessTokens(store: Store): Map<string, StoredAccessToken> {
  let map = store.getData<Map<string, StoredAccessToken>>("auth0.oauth.accessTokens");
  if (!map) {
    map = new Map();
    store.setData("auth0.oauth.accessTokens", map);
  }
  return map;
}

function getRefreshTokens(store: Store): Map<string, StoredRefreshToken> {
  let map = store.getData<Map<string, StoredRefreshToken>>("auth0.oauth.refreshTokens");
  if (!map) {
    map = new Map();
    store.setData("auth0.oauth.refreshTokens", map);
  }
  return map;
}

async function parseTokenBody(c: Context<AppEnv>): Promise<Record<string, string>> {
  const contentType = c.req.header("Content-Type") ?? "";
  const raw = await c.req.text();

  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === "string") out[key] = value;
      }
      return out;
    } catch {
      return {};
    }
  }

  return Object.fromEntries(new URLSearchParams(raw));
}

function parseClientCredentials(
  c: Context<AppEnv>,
  body: Record<string, string>,
): { clientId: string; clientSecret: string } {
  let clientId = body.client_id ?? "";
  let clientSecret = body.client_secret ?? "";

  const authHeader = c.req.header("Authorization") ?? "";
  if (authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    if (sep !== -1) {
      const headerId = decodeURIComponent(decoded.slice(0, sep));
      const headerSecret = decodeURIComponent(decoded.slice(sep + 1));
      if (!clientId) clientId = headerId;
      if (!clientSecret) clientSecret = headerSecret;
    }
  }

  return { clientId, clientSecret };
}

async function createAccessToken(
  store: Store,
  user: Auth0User,
  clientId: string,
  audience: string,
  scope: string,
  issuer: string,
): Promise<string> {
  const { privateKey, kid } = await getSigningKeyPair(store);
  const now = auth0Now(store);

  const claims: Record<string, unknown> = {
    scope,
    azp: clientId,
  };

  // Inject app_metadata fields as custom claims on the access token.
  // In real Auth0, Rules/Actions map metadata fields to namespaced JWT claims.
  // The emulator supports this via token_claim_mappings in seed config, which maps
  // app_metadata keys to JWT claim names (e.g., role -> https://example.com/role).
  // Any app_metadata key that is already a URL is also injected directly.
  if (user.app_metadata && typeof user.app_metadata === "object") {
    const mappings = store.getData<Record<string, string>>("auth0.token_claim_mappings") ?? {};
    for (const [metaKey, value] of Object.entries(user.app_metadata)) {
      if (value === null || value === undefined) continue;
      // Apply configured mappings (e.g., role -> https://example.com/role)
      if (mappings[metaKey]) {
        claims[mappings[metaKey]] = value;
      }
      // URL-namespaced keys pass through directly
      if (metaKey.startsWith("https://")) {
        claims[metaKey] = value;
      }
    }
  }

  const builder = new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setSubject(user.user_id)
    .setIssuer(issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600);

  if (audience) {
    builder.setAudience(audience);
  }

  return builder.sign(privateKey);
}

async function createIdToken(
  store: Store,
  user: Auth0User,
  clientId: string,
  issuer: string,
  nonce?: string,
): Promise<string> {
  const { privateKey, kid } = await getSigningKeyPair(store);
  const now = auth0Now(store);

  const claims: Record<string, unknown> = {
    sub: user.user_id,
    name: user.name,
    given_name: user.given_name,
    family_name: user.family_name,
    nickname: user.nickname,
    email: user.email,
    email_verified: user.email_verified,
    picture: user.picture,
  };
  if (nonce) claims.nonce = nonce;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

async function createOidcAccessToken(store: Store, user: Auth0User, audience: string, issuer: string): Promise<string> {
  const { privateKey, kid } = await getSigningKeyPair(store);
  const now = auth0Now(store);
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(user.user_id)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

async function createOidcIdToken(
  store: Store,
  user: Auth0User,
  clientId: string,
  issuer: string,
  nonce?: string,
): Promise<string> {
  const { privateKey, kid } = await getSigningKeyPair(store);
  const now = auth0Now(store);
  const claims: Record<string, unknown> = { email: user.email, name: user.name };
  if (nonce) claims.nonce = nonce;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(user.user_id)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

function oauthError(c: Context<AppEnv>, status: 400 | 403, error: string, description: string): Response {
  return authenticationApiError(c, status, error, description);
}

function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function authorizeParameters(url: URL, body?: Record<string, string>): Record<string, string> {
  return body ?? Object.fromEntries(url.searchParams);
}

export function oauthRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const auth0Store = getAuth0Store(store);

  // OIDC Discovery
  app.get("/.well-known/openid-configuration", (c) => {
    return c.json({
      issuer: `${baseUrl}/`,
      authorization_endpoint: `${baseUrl}/authorize`,
      device_authorization_endpoint: `${baseUrl}/oauth/device/code`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      grant_types_supported: [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
        "client_credentials",
        "refresh_token",
        "password",
        "http://auth0.com/oauth/grant-type/password-realm",
      ],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
      code_challenge_methods_supported: ["S256"],
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nonce",
        "name",
        "given_name",
        "family_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
      ],
    });
  });

  // JWKS
  app.get("/.well-known/jwks.json", async (c) => {
    const { publicKey, kid } = await getSigningKeyPair(store);
    const jwk = await exportJWK(publicKey);
    return c.json({
      keys: [{ ...jwk, kid, use: "sig", alg: "RS256" }],
    });
  });

  // Public key PEM export
  app.get("/_emulate/public-key.pem", async (c) => {
    const { publicKey } = await getSigningKeyPair(store);
    const pem = await exportSPKI(publicKey);
    return c.text(pem, 200, { "Content-Type": "text/plain" });
  });

  function validateAuthorize(c: Context<AppEnv>, params: Record<string, string>): Response | undefined {
    if (params.response_type !== "code") {
      return oauthError(c, 400, "invalid_request", "response_type must be code");
    }
    const client = auth0Store.oauthClients.findOneBy("client_id", params.client_id ?? "");
    if (!client) return oauthError(c, 400, "invalid_request", "Unknown client_id");
    if (!params.redirect_uri || !client.redirect_uris.includes(params.redirect_uri)) {
      return oauthError(c, 400, "invalid_request", "Invalid redirect_uri");
    }
    if (!params.code_challenge) {
      return oauthError(c, 400, "invalid_request", "code_challenge is required");
    }
    if (params.code_challenge_method !== "S256") {
      return oauthError(c, 400, "invalid_request", "code_challenge_method must be S256");
    }
    return undefined;
  }

  function completeAuthorization(c: Context<AppEnv>, params: Record<string, string>, user: Auth0User): Response {
    if (user.blocked) return c.html(renderErrorPage("Sign in failed", AUTH0_ERRORS.USER_BLOCKED, "auth0"));

    const code = generateAuth0Material(store, "auth0_code");
    getAuthorizationCodes(store).set(code, {
      clientId: params.client_id!,
      redirectUri: params.redirect_uri!,
      codeChallenge: params.code_challenge!,
      userId: user.user_id,
      scope: params.scope ?? "openid profile email",
      audience: params.audience ?? params.client_id!,
      nonce: params.nonce || undefined,
      expiresAt: auth0Now(store) + auth0Lifetime(store, "authorization"),
    });
    const redirect = new URL(params.redirect_uri!);
    redirect.searchParams.set("code", code);
    if (params.state !== undefined) redirect.searchParams.set("state", params.state);
    return c.redirect(redirect.toString(), 302);
  }

  app.get("/authorize", (c) => {
    const params = authorizeParameters(new URL(c.req.url));
    const invalid = validateAuthorize(c, params);
    if (invalid) return invalid;

    const users = auth0Store.users.all();
    const body = users
      .map((user) =>
        renderUserButton({
          letter: (user.name || user.email).trim().slice(0, 1).toUpperCase() || "?",
          login: user.email,
          name: user.name,
          formAction: "/authorize/callback",
          hiddenFields: { ...params, user_id: user.user_id },
        }),
      )
      .join("\n");
    return c.html(
      renderCardPage("Choose an account", `Continue to ${escapeHtml(params.client_id ?? "application")}`, body, "auth0"),
    );
  });

  app.post("/authorize/callback", async (c) => {
    const params = authorizeParameters(new URL(c.req.url), await parseTokenBody(c));
    const invalid = validateAuthorize(c, params);
    if (invalid) return invalid;

    const user = auth0Store.users.findOneBy("user_id", params.user_id ?? "");
    if (!user) return c.html(renderErrorPage("Sign in failed", AUTH0_ERRORS.WRONG_CREDENTIALS, "auth0"));
    return completeAuthorization(c, params, user);
  });

  app.post("/oauth/device/code", async (c) => {
    const body = await parseTokenBody(c);
    const client = auth0Store.oauthClients.findOneBy("client_id", body.client_id ?? "");
    if (!client) return oauthError(c, 400, "invalid_request", "Unknown client_id");
    const deviceCode = generateAuth0Material(store, "auth0_device");
    const userCode = generateAuth0Material(store, "EF", 6).slice(-8).toUpperCase();
    const expiresIn = auth0Lifetime(store, "device");
    getDeviceCodes(store).set(deviceCode, {
      clientId: client.client_id,
      userCode,
      scope: body.scope ?? "openid profile email",
      audience: body.audience ?? (client.audience || client.client_id),
      expiresAt: auth0Now(store) + expiresIn,
      status: "pending",
    });
    return c.json({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${baseUrl}/activate`,
      verification_uri_complete: `${baseUrl}/activate?user_code=${encodeURIComponent(userCode)}`,
      expires_in: expiresIn,
      interval: 1,
    });
  });

  app.get("/activate", (c) => {
    const userCode = new URL(c.req.url).searchParams.get("user_code") ?? "";
    const body = `<form method="post" action="/activate" data-testid="auth0-device-form">
<label for="auth0-user-code">Device code</label>
<input id="auth0-user-code" class="checkout-input" data-testid="auth0-device-user-code" name="user_code" value="${escapeAttr(userCode)}" required/>
<label for="auth0-device-email">Email</label>
<input id="auth0-device-email" class="checkout-input" data-testid="auth0-device-email" type="email" name="email" required/>
<label for="auth0-device-password">Password</label>
<input id="auth0-device-password" class="checkout-input" data-testid="auth0-device-password" type="password" name="password" required/>
<button class="checkout-pay-btn" data-testid="auth0-device-approve" name="decision" value="approve" type="submit">Approve</button>
<button class="user-btn" data-testid="auth0-device-deny" name="decision" value="deny" type="submit" formnovalidate>Deny</button>
</form>`;
    return c.html(renderCardPage("Activate device", "Approve or deny this device request", body, "auth0"));
  });

  app.post("/activate", async (c) => {
    const body = await parseTokenBody(c);
    const entry = Array.from(getDeviceCodes(store).values()).find((grant) => grant.userCode === body.user_code);
    if (!entry) return c.html(renderErrorPage("Unknown device code", "Check the code and try again.", "auth0"));
    if (auth0Now(store) >= entry.expiresAt) {
      return c.html(renderErrorPage("Expired device code", "Start device authorization again.", "auth0"));
    }
    if (body.decision === "deny") {
      entry.status = "denied";
      return c.html(renderCardPage("Request denied", "The device was not authorized.", "", "auth0"));
    }
    const user = auth0Store.users.findOneBy("email", body.email ?? "");
    if (!user || !verifyPassword(body.password ?? "", user.password_hash) || user.blocked) {
      return c.html(renderErrorPage("Approval failed", AUTH0_ERRORS.WRONG_CREDENTIALS, "auth0"));
    }
    entry.status = "approved";
    entry.userId = user.user_id;
    return c.html(renderCardPage("Device approved", "You may return to your device.", "", "auth0"));
  });

  // Token endpoint — uses OAuth2 error format: { error, error_description }
  app.post("/oauth/token", async (c) => {
    const body = await parseTokenBody(c);
    const grantType = body.grant_type ?? "";
    const creds = parseClientCredentials(c, body);

    // Validate client
    const clients = auth0Store.oauthClients.all();
    if (clients.length > 0) {
      const client = clients.find((entry) => entry.client_id === creds.clientId);
      if (!client) {
        return authenticationApiError(c, 401, "access_denied", "Unauthorized");
      }
      if (client.client_secret && client.client_secret !== creds.clientSecret) {
        return authenticationApiError(c, 401, "access_denied", "Unauthorized");
      }
    }

    if (grantType === "authorization_code") {
      const code = body.code ?? "";
      const grant = getAuthorizationCodes(store).get(code);
      if (!grant) return oauthError(c, 400, "invalid_grant", "Unknown or already used authorization code.");
      if (auth0Now(store) >= grant.expiresAt) {
        getAuthorizationCodes(store).delete(code);
        return oauthError(c, 400, "expired_token", "The authorization code has expired.");
      }
      if (creds.clientId !== grant.clientId || body.redirect_uri !== grant.redirectUri) {
        return oauthError(c, 400, "invalid_grant", "The authorization code does not match this request.");
      }
      if (!body.code_verifier || pkceS256(body.code_verifier) !== grant.codeChallenge) {
        return oauthError(c, 400, "invalid_grant", "Invalid code_verifier.");
      }
      const user = auth0Store.users.findOneBy("user_id", grant.userId);
      if (!user) return oauthError(c, 400, "invalid_grant", "The authorization code user no longer exists.");

      getAuthorizationCodes(store).delete(code);
      const issuer = `${baseUrl}/`;
      const accessToken = await createOidcAccessToken(store, user, grant.audience, issuer);
      const idToken = await createOidcIdToken(store, user, grant.clientId, issuer, grant.nonce);
      getAccessTokens(store).set(accessToken, {
        clientId: grant.clientId,
        scope: grant.scope,
        issuedAt: auth0Now(store),
        expiresAt: auth0Now(store) + 3600,
        userAuth0Id: user.user_id,
        audience: grant.audience,
      });
      tokenMap?.set(accessToken, {
        login: user.email,
        id: user.id,
        scopes: grant.scope.split(/\s+/).filter(Boolean),
      });
      return c.json({
        access_token: accessToken,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: grant.scope,
      });
    }

    if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
      const deviceCode = body.device_code ?? "";
      const grant = getDeviceCodes(store).get(deviceCode);
      if (!grant) return oauthError(c, 400, "invalid_grant", "Unknown device_code.");
      if (auth0Now(store) >= grant.expiresAt) {
        getDeviceCodes(store).delete(deviceCode);
        return oauthError(c, 400, "expired_token", "The device code has expired.");
      }
      if (grant.clientId !== creds.clientId) return oauthError(c, 400, "invalid_grant", "Wrong client_id.");
      if (grant.status === "pending") {
        return oauthError(c, 400, "authorization_pending", "The user has not approved this device yet.");
      }
      if (grant.status === "denied") {
        getDeviceCodes(store).delete(deviceCode);
        return oauthError(c, 403, "access_denied", "The user denied this device request.");
      }
      const user = grant.userId ? auth0Store.users.findOneBy("user_id", grant.userId) : undefined;
      if (!user) return oauthError(c, 400, "invalid_grant", "The approved user no longer exists.");

      getDeviceCodes(store).delete(deviceCode);
      const issuer = `${baseUrl}/`;
      const accessToken = await createOidcAccessToken(store, user, grant.audience, issuer);
      const idToken = await createOidcIdToken(store, user, grant.clientId, issuer);
      getAccessTokens(store).set(accessToken, {
        clientId: grant.clientId,
        scope: grant.scope,
        issuedAt: auth0Now(store),
        expiresAt: auth0Now(store) + 3600,
        userAuth0Id: user.user_id,
        audience: grant.audience,
      });
      tokenMap?.set(accessToken, {
        login: user.email,
        id: user.id,
        scopes: grant.scope.split(/\s+/).filter(Boolean),
      });
      return c.json({
        access_token: accessToken,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: grant.scope,
      });
    }

    // client_credentials grant — used to get Management API tokens
    if (grantType === "client_credentials") {
      const audience = body.audience ?? "";
      const now = auth0Now(store);
      const accessToken = generateAuth0Material(store, "auth0_m2m", 20);

      getAccessTokens(store).set(accessToken, {
        clientId: creds.clientId,
        scope: body.scope ?? "",
        issuedAt: now,
        expiresAt: now + 86400,
        userAuth0Id: null,
        audience,
      });

      tokenMap?.set(accessToken, {
        login: creds.clientId,
        id: 0,
        scopes: (body.scope ?? "").split(/\s+/).filter(Boolean),
      });

      debug("auth0.oauth", `[client_credentials] client=${creds.clientId} audience=${audience}`);

      return c.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 86400,
        scope: body.scope ?? "",
      });
    }

    // password-realm grant (Auth0's ROPG extension)
    // password-realm grant (Auth0's ROPG extension)
    if (grantType === "http://auth0.com/oauth/grant-type/password-realm" || grantType === "password") {
      const username = body.username ?? "";
      const password = body.password ?? "";
      const realm = body.realm ?? "Username-Password-Authentication";
      const audience = body.audience ?? "";
      const scope = body.scope ?? "openid profile email";

      const user = auth0Store.users.findOneBy("email", username);
      if (!user || user.connection !== realm || !verifyPassword(password, user.password_hash)) {
        return authenticationApiError(c, 403, "invalid_grant", AUTH0_ERRORS.WRONG_CREDENTIALS);
      }
      if (user.blocked) {
        return authenticationApiError(c, 403, "unauthorized", AUTH0_ERRORS.USER_BLOCKED);
      }

      const now = auth0Now(store);
      const includeRefresh = scope.includes("offline_access");
      const refreshToken = includeRefresh ? generateAuth0Material(store, "auth0_rt", 20) : null;
      const issuer = `${baseUrl}/`;

      // When audience is specified, return a JWT access token (matches real Auth0 behavior).
      // Otherwise return an opaque token.
      const accessToken = audience
        ? await createAccessToken(store, user, creds.clientId, audience, scope, issuer)
        : generateAuth0Material(store, "auth0_at", 20);

      getAccessTokens(store).set(accessToken, {
        clientId: creds.clientId,
        scope,
        issuedAt: now,
        expiresAt: now + 86400,
        userAuth0Id: user.user_id,
        audience,
      });

      if (refreshToken) {
        getRefreshTokens(store).set(refreshToken, {
          clientId: creds.clientId,
          scope,
          userAuth0Id: user.user_id,
          audience,
        });
      }

      tokenMap?.set(accessToken, {
        login: user.email,
        id: user.id,
        scopes: scope.split(/\s+/).filter(Boolean),
      });

      const idToken = await createIdToken(store, user, creds.clientId, issuer);

      debug("auth0.oauth", `[password-realm] user=${user.email}`);

      const response: Record<string, unknown> = {
        access_token: accessToken,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 86400,
        scope,
      };
      if (refreshToken) response.refresh_token = refreshToken;

      return c.json(response);
    }

    // refresh_token grant
    if (grantType === "refresh_token") {
      const refreshToken = body.refresh_token ?? "";
      const existing = getRefreshTokens(store).get(refreshToken);
      if (!existing) {
        return authenticationApiError(c, 403, "invalid_grant", AUTH0_ERRORS.INVALID_REFRESH_TOKEN);
      }

      const user = auth0Store.users.findOneBy("user_id", existing.userAuth0Id);
      if (!user) {
        return authenticationApiError(c, 403, "invalid_grant", AUTH0_ERRORS.INVALID_REFRESH_TOKEN);
      }

      getRefreshTokens(store).delete(refreshToken);

      const now = auth0Now(store);
      const nextRefreshToken = generateAuth0Material(store, "auth0_rt", 20);
      const scope = existing.scope;
      const issuer = `${baseUrl}/`;

      const nextAccessToken = existing.audience
        ? await createAccessToken(store, user, existing.clientId, existing.audience, scope, issuer)
        : generateAuth0Material(store, "auth0_at", 20);

      getAccessTokens(store).set(nextAccessToken, {
        clientId: existing.clientId,
        scope,
        issuedAt: now,
        expiresAt: now + 86400,
        userAuth0Id: user.user_id,
        audience: existing.audience,
      });

      getRefreshTokens(store).set(nextRefreshToken, {
        ...existing,
      });

      tokenMap?.set(nextAccessToken, {
        login: user.email,
        id: user.id,
        scopes: scope.split(/\s+/).filter(Boolean),
      });

      const response: Record<string, unknown> = {
        access_token: nextAccessToken,
        refresh_token: nextRefreshToken,
        token_type: "Bearer",
        expires_in: 86400,
        scope,
      };

      if (scope.includes("openid")) {
        response.id_token = await createIdToken(store, user, existing.clientId, issuer);
      }

      debug("auth0.oauth", `[refresh_token] user=${user.email}`);

      return c.json(response);
    }

    return authenticationApiError(c, 400, "unsupported_grant_type", `Grant type '${grantType}' not allowed.`);
  });

  // Userinfo — uses OAuth2 error format
  app.get("/userinfo", (c) => {
    const token = c.get("authToken") ?? "";
    const access = getAccessTokens(store).get(token);
    if (!access || !access.userAuth0Id) {
      return authenticationApiError(c, 401, "invalid_token", "The access token is invalid.");
    }

    const user = auth0Store.users.findOneBy("user_id", access.userAuth0Id);
    if (!user) {
      return authenticationApiError(c, 401, "invalid_token", "The access token is invalid.");
    }

    return c.json({
      sub: user.user_id,
      name: user.name,
      given_name: user.given_name,
      family_name: user.family_name,
      nickname: user.nickname,
      email: user.email,
      email_verified: user.email_verified,
      picture: user.picture,
    });
  });

  // Revoke token
  app.post("/oauth/revoke", async (c) => {
    const body = await parseTokenBody(c);
    const token = body.token ?? "";
    getAccessTokens(store).delete(token);
    getRefreshTokens(store).delete(token);
    tokenMap?.delete(token);
    return c.body("", 200);
  });
}
