import type { Entity } from "@emulators/core";

export type AgentVaultRole = "proxy" | "member" | "admin";
export type AgentVaultInstanceRole = "owner" | "member" | "no-access";
export type AgentVaultAuthType = "bearer" | "basic" | "api-key" | "custom" | "passthrough";
export type AgentVaultCredentialType = "static" | "oauth" | "dynamic";
export type AgentVaultSubstitutionSurface = "path" | "query" | "header" | "body" | "websocket";
export type AgentVaultUnmatchedHostPolicy = "passthrough" | "deny";

export interface AgentVaultAuth {
  type: AgentVaultAuthType;
  token?: string;
  username?: string;
  password?: string;
  key?: string;
  header?: string;
  prefix?: string;
  headers?: Record<string, string>;
}

export interface AgentVaultSubstitution {
  key: string;
  placeholder: string;
  in?: AgentVaultSubstitutionSurface[];
}

export interface AgentVaultService extends Entity {
  vault_id: string;
  name: string;
  host: string;
  path: string;
  port: number | null;
  enabled: boolean | null;
  auth: AgentVaultAuth;
  substitutions: AgentVaultSubstitution[];
}

export interface AgentVaultVault extends Entity {
  vault_id: string;
  name: string;
  unmatched_host_policy: AgentVaultUnmatchedHostPolicy;
  credential_store: AgentVaultCredentialStoreSummary | null;
}

export interface AgentVaultCredentialStoreSummary {
  kind: "builtin" | "infisical";
  config?: Record<string, unknown>;
  poll_interval_seconds?: number;
  last_sync_status?: string;
  last_synced_at?: string;
  last_sync_error?: string;
}

export interface AgentVaultCredential extends Entity {
  vault_id: string;
  key: string;
  value: string;
  type: AgentVaultCredentialType;
}

export interface AgentVaultOAuthCredential extends Entity {
  vault_id: string;
  key: string;
  authorization_url: string;
  token_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  scope_separator: string;
  disable_pkce: boolean;
  token_auth_method: string;
  access_token: string;
  refresh_token: string;
  connected_at: string | null;
  last_refreshed_at: string | null;
  last_refresh_error: string | null;
}

export interface AgentVaultAgentGrant {
  vault_name: string;
  vault_role: AgentVaultRole;
}

export interface AgentVaultUserGrant {
  vault_name: string;
  vault_role: AgentVaultRole;
}

export interface AgentVaultUser extends Entity {
  email: string;
  role: AgentVaultInstanceRole;
  vaults: AgentVaultUserGrant[];
}

export interface AgentVaultAgent extends Entity {
  agent_id: string;
  name: string;
  role: AgentVaultInstanceRole;
  status: "active" | "revoked";
  token: string;
  vaults: AgentVaultAgentGrant[];
  created_by: string;
  token_expires_at: string | null;
  revoked_at: string | null;
}

export interface AgentVaultSession extends Entity {
  public_id: string;
  token: string;
  vault_id: string;
  vault_name: string;
  vault_role: AgentVaultRole;
  label: string;
  expires_at: string;
  created_by_id: string;
  created_by_type: "user" | "agent" | "session";
}

export interface AgentVaultProposal extends Entity {
  proposal_id: number;
  vault_id: string;
  vault_name: string;
  status: "pending" | "approved" | "rejected";
  services_json: string;
  credentials_json: string;
  message: string;
  user_message: string;
  approval_token: string;
  actor_name: string;
  resolved_at: string | null;
}

export interface AgentVaultUserInvite extends Entity {
  token: string;
  email: string;
  role: AgentVaultInstanceRole;
  vaults: AgentVaultUserGrant[];
  status: "pending" | "accepted" | "revoked" | "expired";
  expires_at: string;
}

export interface AgentVaultRequestLog extends Entity {
  log_id: number;
  vault_id: string;
  ingress: "mitm" | "http" | "emulated";
  method: string;
  host: string;
  path: string;
  matched_service: string;
  credential_keys: string[];
  status: number;
  latency_ms: number;
  error_code: string;
  actor_type: "user" | "agent" | "session";
  actor_id: string;
  actor_name: string;
}
