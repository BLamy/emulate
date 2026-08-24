---
name: agent-vault
description: Emulated Infisical Agent Vault control-plane API for local development and testing. Use when the user needs to test Agent Vault SDK flows, create vaults, set credentials, configure broker service rules, mint scoped proxy sessions, inspect request logs, or work with AGENT_VAULT_ADDR and AGENT_VAULT_TOKEN locally without running the real Agent Vault binary.
allowed-tools: Bash(npx emulate:*), Bash(curl:*)
---

# Agent Vault Emulator

Stateful Agent Vault management API emulation. Vaults, credentials, broker service rules, scoped sessions, agents, and logs persist in memory. This emulator does not run Agent Vault's real TCP CONNECT MITM proxy.

## Start

```bash
npx emulate --service agent-vault
```

Default URL when run alone:

```text
http://localhost:4000
```

When all services run, Agent Vault starts on:

```text
http://localhost:4015
```

## Default Auth

Use the seeded agent token:

```bash
export AGENT_VAULT_ADDR=http://localhost:4000
export AGENT_VAULT_TOKEN=av_agt_default
```

## Main Endpoints

- `POST /v1/vaults`
- `GET /v1/vaults`
- `GET /v1/credentials?vault=default`
- `POST /v1/credentials`
- `GET /v1/vaults/default/services`
- `POST /v1/vaults/default/services`
- `POST /v1/sessions`
- `GET /v1/mitm/ca.pem`
- `GET /v1/agents`
- `GET /v1/vaults/default/logs`
- `GET /`

## Example

```bash
curl -X POST "$AGENT_VAULT_ADDR/v1/credentials" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vault":"default","credentials":{"STRIPE_KEY":"sk_test_123"}}'

curl -X POST "$AGENT_VAULT_ADDR/v1/vaults/default/services" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"services":[{"name":"stripe","host":"api.stripe.com","auth":{"type":"bearer","token":"STRIPE_KEY"}}]}'

curl -X POST "$AGENT_VAULT_ADDR/v1/sessions" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vault":"default","ttl_seconds":3600}'
```
