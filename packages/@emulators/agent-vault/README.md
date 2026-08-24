# @emulators/agent-vault

Agent Vault control-plane API emulator for local development and CI.

It implements the SDK-facing management API for vaults, credentials, services, scoped sessions, agents, MITM CA metadata, request logs, and a browser inspector. It does not run Agent Vault's real TCP CONNECT MITM proxy.

When run through `emulate --service agent-vault`, it starts on `http://localhost:4000`. When all services run together, Agent Vault uses `http://localhost:4015`.
