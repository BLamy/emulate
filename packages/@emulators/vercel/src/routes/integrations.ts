import type { Context } from "@emulators/core";
import type { ContentfulStatusCode } from "@emulators/core";
import type { RouteContext } from "@emulators/core";
import { getVercelStore, type VercelStore } from "../store.js";
import type { VercelIntegrationConfiguration, VercelTeam } from "../entities.js";

function vercelErr(c: Context, status: ContentfulStatusCode, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

function formatConfiguration(config: VercelIntegrationConfiguration) {
  return {
    id: config.uid,
    integrationId: config.integrationId,
    ownerId: config.ownerId,
    userId: config.userId,
    teamId: config.teamId,
    projectSelection: config.projectSelection,
    projects: config.projects,
    scopes: config.scopes,
    slug: config.slug,
    type: config.type,
    status: config.status,
    source: config.source,
    installationType: config.installationType,
    canConfigureOpenTelemetry: config.canConfigureOpenTelemetry,
    externalId: config.externalId,
    createdAt: new Date(config.created_at).getTime(),
    updatedAt: new Date(config.updated_at).getTime(),
    completedAt: config.completedAt,
    disabledAt: config.disabledAt,
    disabledReason: config.disabledReason,
    deletedAt: config.deletedAt,
    deleteRequestedAt: config.deleteRequestedAt,
    customerDeleteRequestedAt: config.customerDeleteRequestedAt,
  };
}

function resolveScopeOwnerId(c: Context, vs: VercelStore): string | null {
  const teamId = c.req.query("teamId");
  const slug = c.req.query("slug");
  if (teamId) {
    const team = vs.teams.findOneBy("uid", teamId as VercelTeam["uid"]);
    if (team) return team.uid;
  } else if (slug) {
    const team = vs.teams.findOneBy("slug", slug as VercelTeam["slug"]);
    if (team) return team.uid;
  }
  return null;
}

export function integrationsRoutes({ app, store }: RouteContext): void {
  const vs = getVercelStore(store);

  app.get("/v1/integrations/configuration/:id", (c) => {
    const auth = c.get("authUser");
    if (!auth) {
      return vercelErr(c, 401, "not_authenticated", "Authentication required");
    }

    const configId = c.req.param("id");
    const config = vs.integrationConfigurations.findOneBy("uid", configId);

    if (!config) {
      return vercelErr(c, 404, "not_found", "The configuration was not found");
    }

    const scopeOwnerId = resolveScopeOwnerId(c, vs);
    if (scopeOwnerId && config.ownerId !== scopeOwnerId) {
      return vercelErr(c, 403, "forbidden", "You do not have permission to access this resource");
    }

    return c.json(formatConfiguration(config));
  });

  app.delete("/v1/integrations/configuration/:id", (c) => {
    const auth = c.get("authUser");
    if (!auth) {
      return vercelErr(c, 401, "not_authenticated", "Authentication required");
    }

    const configId = c.req.param("id");
    const config = vs.integrationConfigurations.findOneBy("uid", configId);

    if (!config) {
      return vercelErr(c, 404, "not_found", "The configuration was not found");
    }

    const scopeOwnerId = resolveScopeOwnerId(c, vs);
    if (scopeOwnerId && config.ownerId !== scopeOwnerId) {
      return vercelErr(c, 403, "forbidden", "You do not have permission to access this resource");
    }

    vs.integrationConfigurations.delete(config.id);

    return c.body(null, 204);
  });
}
