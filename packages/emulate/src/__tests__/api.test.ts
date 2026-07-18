import { describe, it, expect } from "vitest";
import { createEmulator } from "../api.js";

describe("createEmulator", () => {
  it("starts github and returns a url", async () => {
    const github = await createEmulator({ service: "github", port: 14000 });

    expect(github.url).toBe("http://localhost:14000");

    const res = await fetch(`${github.url}/user`, {
      headers: { Authorization: "token test_token_admin" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { login: string };
    expect(body.login).toBe("admin");

    await github.close();
  });

  it("starts multiple services independently", async () => {
    const [github, vercel] = await Promise.all([
      createEmulator({ service: "github", port: 14010 }),
      createEmulator({ service: "vercel", port: 14011 }),
    ]);

    expect(github.url).toBe("http://localhost:14010");
    expect(vercel.url).toBe("http://localhost:14011");

    await Promise.all([github.close(), vercel.close()]);
  });

  it("reset wipes and re-seeds stores", async () => {
    const github = await createEmulator({
      service: "github",
      port: 14020,
      seed: { github: { users: [{ login: "test-user" }] } },
    });

    const createRes = await fetch(`${github.url}/user/repos`, {
      method: "POST",
      headers: {
        Authorization: "token test_token_admin",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "my-repo", private: false }),
    });
    expect(createRes.status).toBe(201);

    github.reset();

    const listRes = await fetch(`${github.url}/user/repos`, {
      headers: { Authorization: "token test_token_admin" },
    });
    expect(listRes.status).toBe(200);
    const repos = (await listRes.json()) as unknown[];
    expect(repos).toHaveLength(0);

    await github.close();
  });

  it("does not grant Slack fallback scopes in strict mode", async () => {
    const slack = await createEmulator({
      service: "slack",
      port: 14030,
      seed: { slack: { strict_scopes: true } },
    });

    const res = await fetch(`${slack.url}/api/chat.postMessage`, {
      method: "POST",
      headers: {
        Authorization: "Bearer arbitrary-slack-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ channel: "C000000001", text: "strict fallback" }),
    });
    const body = (await res.json()) as { ok: boolean; error: string; needed: string; provided: string };
    expect(body).toMatchObject({
      ok: false,
      error: "missing_scope",
      needed: "chat:write",
      provided: "",
    });

    await slack.close();
  });

  it("replays Auth0 authorization material after reset with injected options", async () => {
    const auth0 = await createEmulator({
      service: "auth0",
      port: 14040,
      now: 1_700_000_000,
      seedMaterial: "api-reset",
      seed: {
        auth0: {
          users: [{ email: "api@example.com", password: "ApiTest1!", user_id: "api-user" }],
          oauth_clients: [
            {
              client_id: "api-client",
              client_secret: "api-secret",
              redirect_uris: ["http://localhost:3000/callback"],
            },
          ],
        },
      },
    });

    const authorize = async () => {
      const params = {
        response_type: "code",
        client_id: "api-client",
        redirect_uri: "http://localhost:3000/callback",
        code_challenge: "fixed-s256-challenge",
        code_challenge_method: "S256",
        email: "api@example.com",
        password: "ApiTest1!",
      };
      const response = await fetch(`${auth0.url}/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(params),
        redirect: "manual",
      });
      expect(response.status).toBe(302);
      return new URL(response.headers.get("location")!).searchParams.get("code")!;
    };

    const firstCode = await authorize();
    auth0.reset();

    const cleared = await fetch(`${auth0.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: "api-client",
        client_secret: "api-secret",
        code: firstCode,
        redirect_uri: "http://localhost:3000/callback",
        code_verifier: "not-used",
      }),
    });
    expect(cleared.status).toBe(400);

    expect(await authorize()).toBe(firstCode);
    await auth0.close();
  });

  it("throws on unknown service", async () => {
    // @ts-expect-error testing invalid service name
    await expect(createEmulator({ service: "unknown-svc" })).rejects.toThrow("Unknown service");
  });
});
