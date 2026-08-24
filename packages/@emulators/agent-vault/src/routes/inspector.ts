import type { InspectorTab, RouteContext } from "@emulators/core";
import { escapeHtml, renderInspectorPage } from "@emulators/core";
import { getAgentVaultStore } from "../store.js";
import { credentialKeysForService, formatService, htmlCell, truncate } from "../helpers.js";
import { table } from "./logs.js";

const TABS: InspectorTab[] = [
  { id: "vaults", label: "Vaults", href: "/?tab=vaults" },
  { id: "credentials", label: "Credentials", href: "/?tab=credentials" },
  { id: "services", label: "Services", href: "/?tab=services" },
  { id: "agents", label: "Agents", href: "/?tab=agents" },
  { id: "sessions", label: "Sessions", href: "/?tab=sessions" },
  { id: "logs", label: "Logs", href: "/?tab=logs" },
];

type TabId = (typeof TABS)[number]["id"];

export function inspectorRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const avs = () => getAgentVaultStore(store);

  app.get("/", (c) => {
    const requested = c.req.query("tab") ?? "vaults";
    const active = TABS.some((tab) => tab.id === requested) ? (requested as TabId) : "vaults";
    const body =
      active === "credentials"
        ? credentialsView()
        : active === "services"
          ? servicesView()
          : active === "agents"
            ? agentsView()
            : active === "sessions"
              ? sessionsView()
              : active === "logs"
                ? logsView()
                : vaultsView();
    return c.html(renderInspectorPage("Agent Vault Inspector", TABS, active, body, "Agent Vault"));
  });

  function vaultsView(): string {
    const rows = avs()
      .vaults.all()
      .map((vault) => [
        htmlCell(vault.name),
        htmlCell(avs().credentials.count((credential) => credential.vault_id === vault.vault_id)),
        htmlCell(avs().services.count((service) => service.vault_id === vault.vault_id)),
        htmlCell(vault.unmatched_host_policy),
        htmlCell(vault.created_at),
      ]);
    return section(
      "Vaults",
      table(["Name", "Credentials", "Services", "Unmatched Host", "Created"], rows, "No vaults."),
    );
  }

  function credentialsView(): string {
    const rows = avs()
      .credentials.all()
      .map((credential) => {
        const vault = avs().vaults.findOneBy("vault_id", credential.vault_id);
        return [
          htmlCell(vault?.name),
          htmlCell(credential.key),
          htmlCell(credential.type),
          htmlCell(maskSecret(credential.value)),
        ];
      });
    return section("Credentials", table(["Vault", "Key", "Type", "Value"], rows, "No credentials."));
  }

  function servicesView(): string {
    const rows = avs()
      .services.all()
      .map((service) => {
        const vault = avs().vaults.findOneBy("vault_id", service.vault_id);
        return [
          htmlCell(vault?.name),
          htmlCell(service.name),
          htmlCell(formatService(service).host),
          htmlCell(service.enabled === false ? "disabled" : "enabled"),
          htmlCell(service.auth.type),
          htmlCell(credentialKeysForService(service).join(", ")),
        ];
      });
    return section("Services", table(["Vault", "Name", "Host", "Status", "Auth", "Credentials"], rows, "No services."));
  }

  function agentsView(): string {
    const rows = avs()
      .agents.all()
      .map((agent) => [
        htmlCell(agent.name),
        htmlCell(agent.role),
        htmlCell(agent.status),
        htmlCell(agent.vaults.map((grant) => `${grant.vault_name}:${grant.vault_role}`).join(", ")),
        htmlCell(agent.created_at),
      ]);
    return section("Agents", table(["Name", "Instance Role", "Status", "Vaults", "Created"], rows, "No agents."));
  }

  function sessionsView(): string {
    const rows = avs()
      .sessions.all()
      .map((session) => [
        htmlCell(session.public_id),
        htmlCell(session.vault_name),
        htmlCell(session.vault_role),
        htmlCell(session.label),
        htmlCell(session.expires_at),
      ]);
    return section("Scoped Sessions", table(["ID", "Vault", "Role", "Label", "Expires"], rows, "No scoped sessions."));
  }

  function logsView(): string {
    const rows = avs()
      .requestLogs.all()
      .sort((a, b) => b.log_id - a.log_id)
      .slice(0, 100)
      .map((log) => [
        htmlCell(log.log_id),
        htmlCell(log.method),
        htmlCell(log.host),
        htmlCell(truncate(log.path, 48)),
        htmlCell(log.matched_service),
        htmlCell(log.status),
        htmlCell(log.created_at),
      ]);
    return section(
      "Request Logs",
      table(["ID", "Method", "Host", "Path", "Service", "Status", "Created"], rows, "No logs."),
    );
  }
}

function section(title: string, body: string): string {
  return `<section class="inspector-section"><h2>${escapeHtml(title)}</h2>${body}</section>`;
}

function maskSecret(value: string): string {
  if (!value) return "";
  if (value.length <= 8) return "********";
  return `${escapeHtml(value.slice(0, 4))}...${escapeHtml(value.slice(-4))}`;
}
