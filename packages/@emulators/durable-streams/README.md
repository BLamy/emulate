# @emulators/durable-streams

Durable Streams protocol emulation for local append-only streams.

Part of [emulate](https://github.com/vercel-labs/emulate) - local drop-in replacement services for CI and no-network sandboxes.

## Install

```bash
npm install @emulators/durable-streams
```

## Endpoints

- `PUT /streams/:path` - create a stream
- `HEAD /streams/:path` - read stream metadata
- `GET /streams/:path?offset=-1` - read from the beginning
- `GET /streams/:path?offset=now` - read from the current tail
- `GET /streams/:path?offset=<offset>&live=long-poll` - live poll response
- `GET /streams/:path?offset=<offset>&live=sse` - Server-Sent Events response
- `POST /streams/:path` - append bytes or JSON values
- `POST /streams/:path` with `Stream-Closed: true` - close the stream
- `DELETE /streams/:path` - delete a stream
- `GET /_inspector` - inspect streams and message counts

## Seed Configuration

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

## Links

- [Full documentation](https://emulate.dev/durable-streams)
- [GitHub](https://github.com/vercel-labs/emulate)
