import { Store, type Collection } from "@emulators/core";
import type {
  AgentVaultAgent,
  AgentVaultCredential,
  AgentVaultOAuthCredential,
  AgentVaultProposal,
  AgentVaultRequestLog,
  AgentVaultService,
  AgentVaultSession,
  AgentVaultUser,
  AgentVaultUserInvite,
  AgentVaultVault,
} from "./entities.js";

export interface AgentVaultStore {
  vaults: Collection<AgentVaultVault>;
  credentials: Collection<AgentVaultCredential>;
  oauthCredentials: Collection<AgentVaultOAuthCredential>;
  services: Collection<AgentVaultService>;
  users: Collection<AgentVaultUser>;
  agents: Collection<AgentVaultAgent>;
  sessions: Collection<AgentVaultSession>;
  proposals: Collection<AgentVaultProposal>;
  userInvites: Collection<AgentVaultUserInvite>;
  requestLogs: Collection<AgentVaultRequestLog>;
}

export function getAgentVaultStore(store: Store): AgentVaultStore {
  return {
    vaults: store.collection<AgentVaultVault>("agent-vault.vaults", ["vault_id", "name"]),
    credentials: store.collection<AgentVaultCredential>("agent-vault.credentials", ["vault_id", "key"]),
    oauthCredentials: store.collection<AgentVaultOAuthCredential>("agent-vault.oauth_credentials", ["vault_id", "key"]),
    services: store.collection<AgentVaultService>("agent-vault.services", ["vault_id", "name", "host"]),
    users: store.collection<AgentVaultUser>("agent-vault.users", ["email"]),
    agents: store.collection<AgentVaultAgent>("agent-vault.agents", ["agent_id", "name", "token"]),
    sessions: store.collection<AgentVaultSession>("agent-vault.sessions", ["public_id", "token", "vault_id"]),
    proposals: store.collection<AgentVaultProposal>("agent-vault.proposals", ["proposal_id", "vault_id", "status"]),
    userInvites: store.collection<AgentVaultUserInvite>("agent-vault.user_invites", ["token", "email", "status"]),
    requestLogs: store.collection<AgentVaultRequestLog>("agent-vault.request_logs", [
      "log_id",
      "vault_id",
      "matched_service",
    ]),
  };
}
