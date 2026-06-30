import { describe, expect, it, beforeEach } from "vitest";
import type { Hono, AppEnv } from "@emulators/core";
import { seedFromConfig, getDurableStreamsStore } from "../index.js";
import { STREAM_CLOSED_HEADER, STREAM_OFFSET_HEADER, STREAM_UP_TO_DATE_HEADER, ZERO_OFFSET } from "../helpers.js";
import { authHeaders, createTestApp, testBaseUrl } from "./helpers.js";

describe("Durable Streams plugin", () => {
  let app: Hono<AppEnv>;

  beforeEach(() => {
    app = createTestApp().app;
  });

  it("creates, appends, heads, and reads a JSON stream", async () => {
    const create = await app.request(`${testBaseUrl}/streams/events`, {
      method: "PUT",
      headers: authHeaders("application/json"),
      body: "[]",
    });
    expect(create.status).toBe(201);
    expect(create.headers.get(STREAM_OFFSET_HEADER)).toBe(ZERO_OFFSET);

    const append = await app.request(`${testBaseUrl}/streams/events`, {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ type: "created", id: 1 }),
    });
    expect(append.status).toBe(204);
    const offset = append.headers.get(STREAM_OFFSET_HEADER);
    expect(offset).toMatch(/^\d+_\d+$/);
    expect(offset).not.toBe(ZERO_OFFSET);

    const head = await app.request(`${testBaseUrl}/streams/events`, {
      method: "HEAD",
      headers: authHeaders(),
    });
    expect(head.status).toBe(200);
    expect(head.headers.get(STREAM_OFFSET_HEADER)).toBe(offset);

    const read = await app.request(`${testBaseUrl}/streams/events?offset=-1`, {
      method: "GET",
      headers: authHeaders(),
    });
    expect(read.status).toBe(200);
    expect(read.headers.get(STREAM_UP_TO_DATE_HEADER)).toBe("true");
    expect(await read.json()).toEqual([{ type: "created", id: 1 }]);
  });

  it("returns idempotent create for matching stream configuration", async () => {
    await app.request(`${testBaseUrl}/streams/idempotent`, {
      method: "PUT",
      headers: authHeaders("text/plain"),
    });

    const createAgain = await app.request(`${testBaseUrl}/streams/idempotent`, {
      method: "PUT",
      headers: authHeaders("text/plain"),
    });

    expect(createAgain.status).toBe(200);
  });

  it("rejects appends with a mismatched content type", async () => {
    await app.request(`${testBaseUrl}/streams/text`, {
      method: "PUT",
      headers: authHeaders("text/plain"),
    });

    const append = await app.request(`${testBaseUrl}/streams/text`, {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ wrong: true }),
    });

    expect(append.status).toBe(409);
  });

  it("closes streams and exposes the closed header on tail reads", async () => {
    await app.request(`${testBaseUrl}/streams/close-me`, {
      method: "PUT",
      headers: authHeaders("text/plain"),
    });

    const close = await app.request(`${testBaseUrl}/streams/close-me`, {
      method: "POST",
      headers: { ...authHeaders(), [STREAM_CLOSED_HEADER]: "true" },
    });
    expect(close.status).toBe(204);
    expect(close.headers.get(STREAM_CLOSED_HEADER)).toBe("true");

    const read = await app.request(`${testBaseUrl}/streams/close-me?offset=now`, {
      method: "GET",
      headers: authHeaders(),
    });
    expect(read.status).toBe(200);
    expect(read.headers.get(STREAM_CLOSED_HEADER)).toBe("true");
  });

  it("supports idempotent producer headers", async () => {
    await app.request(`${testBaseUrl}/streams/producer`, {
      method: "PUT",
      headers: authHeaders("application/json"),
    });

    const first = await app.request(`${testBaseUrl}/streams/producer`, {
      method: "POST",
      headers: {
        ...authHeaders("application/json"),
        "Producer-Id": "p1",
        "Producer-Epoch": "0",
        "Producer-Seq": "0",
      },
      body: JSON.stringify({ batch: 1 }),
    });
    expect(first.status).toBe(200);

    const duplicate = await app.request(`${testBaseUrl}/streams/producer`, {
      method: "POST",
      headers: {
        ...authHeaders("application/json"),
        "Producer-Id": "p1",
        "Producer-Epoch": "0",
        "Producer-Seq": "0",
      },
      body: JSON.stringify({ batch: 1 }),
    });
    expect(duplicate.status).toBe(204);

    const gap = await app.request(`${testBaseUrl}/streams/producer`, {
      method: "POST",
      headers: {
        ...authHeaders("application/json"),
        "Producer-Id": "p1",
        "Producer-Epoch": "0",
        "Producer-Seq": "2",
      },
      body: JSON.stringify({ batch: 2 }),
    });
    expect(gap.status).toBe(409);
    expect(gap.headers.get("Producer-Expected-Seq")).toBe("1");
  });

  it("seeds configured streams", async () => {
    const { store } = createTestApp();
    seedFromConfig(store, testBaseUrl, {
      streams: [{ path: "seeded/events", content_type: "application/json", body: JSON.stringify([{ seeded: true }]) }],
    });

    const ds = getDurableStreamsStore(store);
    expect(ds.streams.findOneBy("path", "/seeded/events")).toBeTruthy();
    expect(ds.messages.findBy("stream_path", "/seeded/events")).toHaveLength(1);
  });

  it("renders an inspector", async () => {
    const res = await app.request(`${testBaseUrl}/_inspector`, {
      method: "GET",
      headers: authHeaders(),
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Durable Streams");
    expect(html).toContain("/streams/emulate-default");
  });
});
