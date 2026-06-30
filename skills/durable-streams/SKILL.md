---
name: durable-streams
description: Durable Streams protocol emulator for local append-only streams. Use when the user needs to create, append to, read, close, or test Durable Streams without a network service, or wants to point @durable-streams/client at emulate. Triggers include "Durable Streams emulator", "emulate durable streams", "local durable streams", "stream append", "Stream-Next-Offset", or "@durable-streams/client".
allowed-tools: Bash(npx emulate:*)
---

# Durable Streams Emulator

Durable Streams protocol emulation for local append-only streams. State is in-memory unless embedded through emulate's shared persistence adapter.

## Start

```bash
npx emulate --service durable-streams
```

Default URL when all services run: `http://localhost:4008`.

For one service on the base port:

```bash
npx emulate --service durable-streams --port 4000
```

## Environment

```bash
DURABLE_STREAMS_EMULATOR_URL=http://localhost:4008
```

## Client Usage

```typescript
import { DurableStream, stream } from "@durable-streams/client";

const baseUrl = process.env.DURABLE_STREAMS_EMULATOR_URL ?? "http://localhost:4008";
const url = `${baseUrl}/streams/events`;

await DurableStream.create({
  url,
  contentType: "application/json",
  headers: { Authorization: "Bearer test_token_admin" },
});

await fetch(url, {
  method: "POST",
  headers: {
    Authorization: "Bearer test_token_admin",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ type: "created", id: 1 }),
});

const res = await stream({
  url,
  headers: { Authorization: "Bearer test_token_admin" },
  offset: "-1",
  live: false,
});

const events = await res.json();
```

## Seed Config

```yaml
durable-streams:
  streams:
    - path: /streams/events
      content_type: application/json
      body: "[]"
    - path: /streams/logs
      content_type: text/plain
      body: "ready\n"
```

Default seed: `/streams/emulate-default` as an empty JSON stream.

## Protocol Coverage

- `PUT`, `HEAD`, `GET`, `POST`, and `DELETE` stream operations
- `offset`, `live=long-poll`, and `live=sse` reads
- JSON-mode append validation and array response formatting
- `Stream-Seq`, `Stream-TTL`, `Stream-Expires-At`, and `Stream-Closed`
- Idempotent producer headers: `Producer-Id`, `Producer-Epoch`, and `Producer-Seq`
- Basic fork creation with `Stream-Forked-From` and `Stream-Fork-Offset`
- Inspector at `GET /_inspector`

Current limits: no full subscription APIs and no blocking long-poll waits.
