# @emulators/auth0

Auth0 identity platform emulation with OAuth 2.0 / OIDC, Management API v2, user lifecycle, email verification, and log event streaming.

Part of [emulate](https://github.com/vercel-labs/emulate) — local drop-in replacement services for CI and no-network sandboxes.

## Install

```bash
npm install @emulators/auth0
```

## Endpoints

### Authentication API

- `GET /authorize` — authorization code login with mandatory PKCE `S256`
- `POST /authorize` — submit the authorization login form
- `POST /oauth/device/code` — begin device authorization
- `GET /activate` — device approval and denial form
- `POST /activate` — submit a device decision
- `POST /oauth/token` — token endpoint (authorization_code, device_code, client_credentials, password-realm, refresh_token)

Browser credential, unknown-code, and expired-code form refusals render an explanatory
HTML page with status 200 so they remain inspectable without a browser console resource
error. OAuth protocol refusals from `/authorize` validation and `/oauth/token` retain
their documented 4xx status and JSON error taxonomy.

- `GET /userinfo` — user profile from access token
- `POST /oauth/revoke` — revoke refresh token

### Management API v2

- `POST /api/v2/users` — create user
- `GET /api/v2/users/:id` — get user by ID
- `GET /api/v2/users-by-email` — search users by email
- `PATCH /api/v2/users/:id` — update user
- `POST /api/v2/tickets/email-verification` — create email verification ticket

### OIDC Discovery

- `GET /.well-known/openid-configuration` — OpenID Connect discovery
- `GET /.well-known/jwks.json` — JSON Web Key Set (RS256)
- `GET /_emulate/public-key.pem` — RSA public key in PEM format

### Inspector

- `GET /` — tabbed UI showing users, log events, OAuth clients, and connections

## Grant Types

| Grant type                                         | Use                                               |
| -------------------------------------------------- | ------------------------------------------------- |
| `client_credentials`                               | Machine-to-machine tokens (Management API access) |
| `authorization_code`                               | Browser login with mandatory PKCE `S256`          |
| `urn:ietf:params:oauth:grant-type:device_code`     | Poll a browser-approved device grant              |
| `http://auth0.com/oauth/grant-type/password-realm` | User login with email + password + connection     |
| `refresh_token`                                    | Exchange refresh token for new tokens             |

## Log Event Streaming

The emulator dispatches Auth0 log events via webhook when state changes occur:

| Type  | Event             | Trigger                      |
| ----- | ----------------- | ---------------------------- |
| `ss`  | Successful Signup | User created                 |
| `fs`  | Failed Signup     | Create user failed           |
| `sv`  | Email Verified    | Verification ticket consumed |
| `scp` | Password Changed  | User password updated        |

Configure webhook subscribers in the seed config via `log_streams`.

## Error Fidelity

Error responses match Auth0's actual format so SDK error handling works unchanged:

- Authentication API errors use OAuth2 format: `{ error, error_description }`
- Management API errors use Auth0 format: `{ statusCode, error, message, errorCode }`

## Seed Configuration

```yaml
auth0:
  now: 1700000000
  seed: repeatable-test-run
  connections:
    - name: Username-Password-Authentication
  users:
    - email: admin@example.com
      password: Admin1234!
      email_verified: true
      app_metadata:
        role: ADMIN
  oauth_clients:
    - client_id: my-m2m-client
      client_secret: my-secret
      name: Backend Service
      grant_types: [client_credentials]
      audience: https://api.example.com
  log_streams:
    - url: http://localhost:9000/auth0-events
  signing_key:
    private_key_pem: |
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
    public_key_pem: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    kid: my-custom-kid
```

When `signing_key` is omitted, a random RS256 key pair is generated on first request. When provided, all ID tokens and the JWKS endpoint use the configured key, enabling static JWT validation in your backend.

The committed `fixtures/test-keypair.private.jwk.json` and
`fixtures/test-keypair.public.jwk.json` pair is reserved for deterministic integration
tests. Convert the JWKs to PEM for `signing_key` and retain
`kid: eforest-test-2026`. Never use this public test key outside local evidence runs.

`now` freezes Unix time in seconds and `seed` makes authorization codes, device codes, and user codes repeatable. The same values are available through `createEmulator({ now, seedMaterial })` and the CLI flags `--now` and `--seed-material`. Outstanding authorization and device grants are cleared by `reset()`.

## Links

- [Full documentation](https://emulate.dev)
- [GitHub](https://github.com/vercel-labs/emulate)
