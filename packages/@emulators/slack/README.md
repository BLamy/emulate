# @emulators/slack

Fully stateful Slack Web API emulation with channels, messages, threads, reactions, OAuth v2, and incoming webhooks. Chat writes preserve common rich message fields such as `blocks`, `attachments`, `metadata`, formatting flags, unfurl flags, and client message ids.

Part of [emulate](https://github.com/vercel-labs/emulate) — local drop-in replacement services for CI and no-network sandboxes.

## Install

```bash
npm install @emulators/slack
```

## Endpoints

### Auth & Chat
- `POST /api/auth.test` — test authentication
- `POST /api/chat.postMessage` — post message with text or rich payload fields (supports threads via `thread_ts`)
- `POST /api/chat.update` — update message text and rich payload fields
- `POST /api/chat.delete` — delete message
- `POST /api/chat.meMessage` — /me message

### Conversations
- `POST /api/conversations.list` — list channels (cursor pagination)
- `POST /api/conversations.info` — get channel info
- `POST /api/conversations.create` — create channel
- `POST /api/conversations.history` — channel history with rich message fields
- `POST /api/conversations.replies` — thread replies with rich message fields
- `POST /api/conversations.join` / `conversations.leave` — join/leave
- `POST /api/conversations.members` — list members

### Users & Reactions
- `POST /api/users.list` — list users (cursor pagination)
- `POST /api/users.info` — get user info
- `POST /api/users.lookupByEmail` — lookup by email
- `POST /api/reactions.add` / `reactions.remove` / `reactions.get` — manage reactions

### Team, Bots & Webhooks
- `POST /api/team.info` — workspace info
- `POST /api/bots.info` — bot info
- `POST /services/:teamId/:botId/:webhookId` — incoming webhook with text or rich payload fields

### OAuth
- `GET /oauth/v2/authorize` — authorization (shows user picker)
- `POST /api/oauth.v2.access` — token exchange

## Auth

All Web API endpoints require `Authorization: Bearer <token>`. OAuth v2 flow with user picker UI.

## Seed Configuration

```yaml
slack:
  team:
    name: My Workspace
    domain: my-workspace
  users:
    - name: developer
      real_name: Developer
      email: dev@example.com
  channels:
    - name: general
      topic: General discussion
    - name: random
      topic: Random stuff
  bots:
    - name: my-bot
  oauth_apps:
    - client_id: "12345.67890"
      client_secret: example_client_secret
      name: My Slack App
      redirect_uris:
        - http://localhost:3000/api/auth/callback/slack
```

## Links

- [Full documentation](https://emulate.dev/slack)
- [GitHub](https://github.com/vercel-labs/emulate)
