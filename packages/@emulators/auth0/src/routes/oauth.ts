import { createHash } from "node:crypto";
import {
  SignJWT,
  exportJWK,
  exportSPKI,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  type CryptoKey as JoseCryptoKey,
} from "jose";
import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import {
  bodyStr,
  constantTimeSecretEqual,
  debug,
  escapeHtml,
  matchesRedirectUri,
  renderAuthForm,
  renderCardPage,
  renderErrorPage,
  renderUserButton,
} from "@emulators/core";
import type { Auth0Connection, Auth0User } from "../entities.js";
import { generateToken, verifyPassword } from "../helpers.js";
import { AUTH0_ERRORS, authenticationApiError } from "../route-helpers.js";
import { getAuth0Store } from "../store.js";

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

type PendingAuthorizationCode = {
  clientId: string;
  redirectUri: string;
  scope: string;
  nonce: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  audience: string;
  userAuth0Id: string;
  createdAt: number;
};

const AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;

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

function getPendingAuthorizationCodes(store: Store): Map<string, PendingAuthorizationCode> {
  let map = store.getData<Map<string, PendingAuthorizationCode>>("auth0.oauth.pendingAuthorizationCodes");
  if (!map) {
    map = new Map();
    store.setData("auth0.oauth.pendingAuthorizationCodes", map);
  }
  return map;
}

function isAuthorizationCodeExpired(code: PendingAuthorizationCode): boolean {
  return Date.now() - code.createdAt > AUTHORIZATION_CODE_TTL_MS;
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
  const now = Math.floor(Date.now() / 1000);

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
    .setExpirationTime("1h");

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
  nonce?: string | null,
): Promise<string> {
  const { privateKey, kid } = await getSigningKeyPair(store);
  const now = Math.floor(Date.now() / 1000);

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
    .setExpirationTime("1h")
    .sign(privateKey);
}

type AuthorizationRequest = {
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope: string;
  state: string;
  nonce: string;
  connection: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  audience: string;
};

function requestFromQuery(c: Context<AppEnv>): AuthorizationRequest {
  return {
    clientId: c.req.query("client_id") ?? "",
    redirectUri: c.req.query("redirect_uri") ?? "",
    responseType: c.req.query("response_type") ?? "",
    scope: c.req.query("scope") ?? "openid profile email",
    state: c.req.query("state") ?? "",
    nonce: c.req.query("nonce") ?? "",
    connection: c.req.query("connection") ?? "",
    codeChallenge: c.req.query("code_challenge") ?? "",
    codeChallengeMethod: c.req.query("code_challenge_method") ?? "",
    audience: c.req.query("audience") ?? "",
  };
}

function requestFromBody(body: Record<string, unknown>): AuthorizationRequest {
  return {
    clientId: bodyStr(body.client_id),
    redirectUri: bodyStr(body.redirect_uri),
    responseType: bodyStr(body.response_type),
    scope: bodyStr(body.scope) || "openid profile email",
    state: bodyStr(body.state),
    nonce: bodyStr(body.nonce),
    connection: bodyStr(body.connection),
    codeChallenge: bodyStr(body.code_challenge),
    codeChallengeMethod: bodyStr(body.code_challenge_method),
    audience: bodyStr(body.audience),
  };
}

function requestHiddenFields(request: AuthorizationRequest): Record<string, string> {
  return {
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    response_type: request.responseType,
    scope: request.scope,
    state: request.state,
    nonce: request.nonce,
    connection: request.connection,
    code_challenge: request.codeChallenge,
    code_challenge_method: request.codeChallengeMethod,
    audience: request.audience,
  };
}

function validateAuthorizationRequest(
  store: Store,
  request: AuthorizationRequest,
): { clientName: string; error: string | null } {
  if (request.responseType !== "code") {
    return { clientName: "", error: "This emulator supports response_type=code only." };
  }
  if (!request.redirectUri) {
    return { clientName: "", error: "redirect_uri is required." };
  }
  try {
    const redirect = new URL(request.redirectUri);
    if (!new Set(["http:", "https:"]).has(redirect.protocol) || redirect.username || redirect.password) {
      return { clientName: "", error: "redirect_uri must be an HTTP(S) URL without credentials." };
    }
  } catch {
    return { clientName: "", error: "redirect_uri is invalid." };
  }

  const clients = getAuth0Store(store).oauthClients.all();
  if (clients.length === 0) return { clientName: "", error: null };
  const client = clients.find((entry) => entry.client_id === request.clientId);
  if (!client) return { clientName: "", error: "The client_id is not registered." };
  if (!matchesRedirectUri(request.redirectUri, client.redirect_uris)) {
    return { clientName: "", error: "The redirect_uri is not registered for this application." };
  }
  if (!client.grant_types.includes("authorization_code")) {
    return { clientName: "", error: "The client is not configured for the authorization_code grant." };
  }
  if (request.codeChallenge && !["plain", "S256"].includes(request.codeChallengeMethod)) {
    return { clientName: "", error: "Unsupported code_challenge_method." };
  }
  return { clientName: client.name, error: null };
}

function isDatabaseConnection(connection: Auth0Connection): boolean {
  return connection.strategy === "auth0" || connection.strategy === "database";
}

function connectionLabel(connection: Auth0Connection): string {
  if (connection.display_name) return connection.display_name;
  if (isDatabaseConnection(connection)) return "Username and password";
  return `Continue with ${connection.strategy}`;
}

function findConfiguredUser(store: Store, userId: string): Auth0User | undefined {
  const normalized = userId.startsWith("auth0|") ? userId : `auth0|${userId}`;
  return getAuth0Store(store).users.findOneBy("user_id", normalized);
}

function issueAuthorizationCode(store: Store, request: AuthorizationRequest, user: Auth0User): string {
  const code = generateToken("auth0_code");
  getPendingAuthorizationCodes(store).set(code, {
    clientId: request.clientId,
    redirectUri: request.redirectUri,
    scope: request.scope,
    nonce: request.nonce || null,
    codeChallenge: request.codeChallenge || null,
    codeChallengeMethod: request.codeChallengeMethod || null,
    audience: request.audience,
    userAuth0Id: user.user_id,
    createdAt: Date.now(),
  });
  return code;
}

function redirectWithCode(c: Context<AppEnv>, request: AuthorizationRequest, code: string): Response {
  const target = new URL(request.redirectUri);
  target.searchParams.set("code", code);
  if (request.state) target.searchParams.set("state", request.state);
  return c.redirect(target.toString(), 302);
}

function renderAuthorizationPage(
  store: Store,
  baseUrl: string,
  request: AuthorizationRequest,
  clientName: string,
  error?: string,
  selectedConnection?: Auth0Connection,
): string {
  const auth0Store = getAuth0Store(store);
  const connections = selectedConnection ? [selectedConnection] : auth0Store.connections.all();
  const databaseConnections = connections.filter(isDatabaseConnection);
  const socialConnections = connections.filter((connection) => !isDatabaseConnection(connection));
  const databaseNames = new Set(databaseConnections.map((connection) => connection.name));
  const defaultEmail = auth0Store.users.all().find((user) => databaseNames.has(user.connection))?.email ?? "";
  const forms: string[] = [];

  if (databaseConnections.length > 0) {
    const connection = databaseConnections[0];
    forms.push(
      `<div class="info-text">Auth0 emulator: <span data-testid="auth0-emulator-url">${escapeHtml(baseUrl)}</span></div>`,
      renderAuthForm({
        formAction: "/authorize/password",
        hiddenFields: {
          ...requestHiddenFields(request),
          connection: connection.name,
        },
        email: defaultEmail,
        error,
        emailTestId: "email-input",
        passwordTestId: "password-input",
        formTestId: "login-form",
        submitTestId: "login-button",
        submitLabel: "Sign in with username and password",
      }),
    );
  } else if (error) {
    forms.push(`<div data-testid="login-error" class="auth-error" role="alert">${escapeHtml(error)}</div>`);
  }

  if (socialConnections.length > 0) {
    if (forms.length > 0) forms.push('<div class="auth-divider">or continue with</div>');
    for (const connection of socialConnections) {
      forms.push(
        renderUserButton({
          letter: (connectionLabel(connection)[0] ?? "?").toUpperCase(),
          login: connectionLabel(connection),
          name: `Auth0 connection · ${connection.strategy}`,
          formAction: "/authorize/connection",
          hiddenFields: {
            ...requestHiddenFields(request),
            connection: connection.name,
          },
          testId: `auth0-connection-${connection.name.replace(/[^A-Za-z0-9_-]/g, "-")}`,
        }),
      );
    }
  }

  if (forms.length === 0) forms.push('<p class="empty">No enabled Auth0 connections are configured.</p>');
  const subtitle = clientName
    ? `Sign in to <strong>${escapeHtml(clientName)}</strong> with Auth0.`
    : "Choose an Auth0 connection or use a seeded database user.";
  return renderCardPage("Sign in to Auth0", subtitle, forms.join("\n"), "Auth0");
}

export function oauthRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const auth0Store = getAuth0Store(store);

  // OIDC Discovery
  app.get("/.well-known/openid-configuration", (c) => {
    return c.json({
      issuer: `${baseUrl}/`,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      response_types_supported: ["code", "token"],
      grant_types_supported: [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "http://auth0.com/oauth/grant-type/password-realm",
      ],
      response_modes_supported: ["query"],
      code_challenge_methods_supported: ["plain", "S256"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
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

  // Authorization endpoint — a small Universal Login surface backed by seeded connections.
  app.get("/authorize", (c) => {
    const request = requestFromQuery(c);
    const validation = validateAuthorizationRequest(store, request);
    if (validation.error) {
      return c.html(renderErrorPage("Authorization request rejected", validation.error, "Auth0"), 400);
    }
    const selected = request.connection ? auth0Store.connections.findOneBy("name", request.connection) : undefined;
    if (request.connection && !selected) {
      return c.html(
        renderErrorPage("Connection not found", "The requested Auth0 connection is not configured.", "Auth0"),
        400,
      );
    }
    return c.html(renderAuthorizationPage(store, baseUrl, request, validation.clientName, undefined, selected));
  });

  app.post("/authorize/password", async (c) => {
    const body = await c.req.parseBody();
    const request = requestFromBody(body);
    const validation = validateAuthorizationRequest(store, request);
    if (validation.error) {
      return c.html(renderErrorPage("Authorization request rejected", validation.error, "Auth0"), 400);
    }
    const connection = auth0Store.connections.findOneBy("name", request.connection);
    if (!connection || !isDatabaseConnection(connection)) {
      return c.html(
        renderErrorPage("Connection unavailable", "The selected connection is not a database connection.", "Auth0"),
        400,
      );
    }
    const email = bodyStr(body.email).trim();
    const password = bodyStr(body.password);
    const user = auth0Store.users.findBy("email", email).find((candidate) => candidate.connection === connection.name);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return c.html(
        renderAuthorizationPage(store, baseUrl, request, validation.clientName, AUTH0_ERRORS.WRONG_CREDENTIALS),
      );
    }
    if (user.blocked) {
      return c.html(renderAuthorizationPage(store, baseUrl, request, validation.clientName, AUTH0_ERRORS.USER_BLOCKED));
    }
    return redirectWithCode(c, request, issueAuthorizationCode(store, request, user));
  });

  app.post("/authorize/connection", async (c) => {
    const body = await c.req.parseBody();
    const request = requestFromBody(body);
    const validation = validateAuthorizationRequest(store, request);
    if (validation.error) {
      return c.html(renderErrorPage("Authorization request rejected", validation.error, "Auth0"), 400);
    }
    const connection = auth0Store.connections.findOneBy("name", request.connection);
    if (!connection) {
      return c.html(
        renderErrorPage("Connection not found", "The requested Auth0 connection is not configured.", "Auth0"),
        400,
      );
    }
    if (isDatabaseConnection(connection)) {
      return c.html(renderAuthorizationPage(store, baseUrl, request, validation.clientName, undefined, connection));
    }

    const configured = connection.default_user_id ? findConfiguredUser(store, connection.default_user_id) : undefined;
    if (configured && !configured.blocked) {
      return redirectWithCode(c, request, issueAuthorizationCode(store, request, configured));
    }

    const users = auth0Store.users.all().filter((user) => user.connection === connection.name && !user.blocked);
    if (users.length === 1) return redirectWithCode(c, request, issueAuthorizationCode(store, request, users[0]));
    if (users.length === 0) {
      return c.html(
        renderErrorPage("No seeded account", `No user is configured for ${connectionLabel(connection)}.`, "Auth0"),
        400,
      );
    }

    const buttons = users
      .map((user) =>
        renderUserButton({
          letter: (user.email[0] ?? "?").toUpperCase(),
          login: user.email,
          name: user.name,
          email: user.email,
          formAction: "/authorize/social",
          hiddenFields: {
            ...requestHiddenFields(request),
            user_id: user.user_id,
          },
        }),
      )
      .join("\n");
    return c.html(
      renderCardPage(`Continue with ${connectionLabel(connection)}`, "Choose a seeded account.", buttons, "Auth0"),
    );
  });

  app.post("/authorize/social", async (c) => {
    const body = await c.req.parseBody();
    const request = requestFromBody(body);
    const validation = validateAuthorizationRequest(store, request);
    if (validation.error) {
      return c.html(renderErrorPage("Authorization request rejected", validation.error, "Auth0"), 400);
    }
    const connection = auth0Store.connections.findOneBy("name", request.connection);
    const user = auth0Store.users.findOneBy("user_id", bodyStr(body.user_id));
    if (!connection || !user || user.connection !== connection.name || user.blocked) {
      return c.html(
        renderErrorPage("Account unavailable", "The selected seeded account is not available.", "Auth0"),
        400,
      );
    }
    return redirectWithCode(c, request, issueAuthorizationCode(store, request, user));
  });

  // Token endpoint — uses OAuth2 error format: { error, error_description }
  app.post("/oauth/token", async (c) => {
    const body = await parseTokenBody(c);
    const grantType = body.grant_type ?? "";
    const creds = parseClientCredentials(c, body);

    // Validate client
    const clients = auth0Store.oauthClients.all();
    const configuredClient = clients.find((entry) => entry.client_id === creds.clientId);
    if (clients.length > 0) {
      if (!configuredClient) {
        return authenticationApiError(c, 401, "access_denied", "Unauthorized");
      }
      if (
        configuredClient.client_secret &&
        !constantTimeSecretEqual(configuredClient.client_secret, creds.clientSecret)
      ) {
        return authenticationApiError(c, 401, "access_denied", "Unauthorized");
      }
    }

    if (grantType === "authorization_code") {
      const code = body.code ?? "";
      const pending = getPendingAuthorizationCodes(store).get(code);
      if (!pending || isAuthorizationCodeExpired(pending)) {
        if (pending) getPendingAuthorizationCodes(store).delete(code);
        return authenticationApiError(c, 400, "invalid_grant", "The authorization code is invalid or expired.");
      }
      if (pending.clientId !== creds.clientId || pending.redirectUri !== (body.redirect_uri ?? "")) {
        return authenticationApiError(c, 400, "invalid_grant", "The authorization code does not match this client.");
      }
      if (pending.codeChallenge) {
        const verifier = body.code_verifier ?? "";
        const expected =
          pending.codeChallengeMethod === "S256" ? createHash("sha256").update(verifier).digest("base64url") : verifier;
        if (!verifier || expected !== pending.codeChallenge) {
          return authenticationApiError(c, 400, "invalid_grant", "The code verifier is invalid.");
        }
      }

      const user = auth0Store.users.findOneBy("user_id", pending.userAuth0Id);
      if (!user || user.blocked) {
        return authenticationApiError(c, 400, "invalid_grant", "The authorization code user is unavailable.");
      }
      getPendingAuthorizationCodes(store).delete(code);

      const now = Math.floor(Date.now() / 1000);
      const includeRefresh = pending.scope.includes("offline_access");
      const refreshToken = includeRefresh ? generateToken("auth0_rt") : null;
      const issuer = `${baseUrl}/`;
      const accessToken = pending.audience
        ? await createAccessToken(store, user, creds.clientId, pending.audience, pending.scope, issuer)
        : generateToken("auth0_at");

      getAccessTokens(store).set(accessToken, {
        clientId: creds.clientId,
        scope: pending.scope,
        issuedAt: now,
        expiresAt: now + 86400,
        userAuth0Id: user.user_id,
        audience: pending.audience,
      });
      if (refreshToken) {
        getRefreshTokens(store).set(refreshToken, {
          clientId: creds.clientId,
          scope: pending.scope,
          userAuth0Id: user.user_id,
          audience: pending.audience,
        });
      }
      tokenMap?.set(accessToken, {
        login: user.email,
        id: user.id,
        scopes: pending.scope.split(/\s+/).filter(Boolean),
      });

      const response: Record<string, unknown> = {
        access_token: accessToken,
        id_token: await createIdToken(store, user, creds.clientId, issuer, pending.nonce),
        token_type: "Bearer",
        expires_in: 86400,
        scope: pending.scope,
      };
      if (refreshToken) response.refresh_token = refreshToken;
      debug("auth0.oauth", `[authorization_code] user=${user.email}`);
      return c.json(response);
    }

    // client_credentials grant — used to get Management API tokens
    if (grantType === "client_credentials") {
      const audience = body.audience ?? "";
      const now = Math.floor(Date.now() / 1000);
      const accessToken = generateToken("auth0_m2m");

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

      const now = Math.floor(Date.now() / 1000);
      const includeRefresh = scope.includes("offline_access");
      const refreshToken = includeRefresh ? generateToken("auth0_rt") : null;
      const issuer = `${baseUrl}/`;

      // When audience is specified, return a JWT access token (matches real Auth0 behavior).
      // Otherwise return an opaque token.
      const accessToken = audience
        ? await createAccessToken(store, user, creds.clientId, audience, scope, issuer)
        : generateToken("auth0_at");

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

      const now = Math.floor(Date.now() / 1000);
      const nextRefreshToken = generateToken("auth0_rt");
      const scope = existing.scope;
      const issuer = `${baseUrl}/`;

      const nextAccessToken = existing.audience
        ? await createAccessToken(store, user, existing.clientId, existing.audience, scope, issuer)
        : generateToken("auth0_at");

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
