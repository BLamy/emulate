package clerk

import (
	"net/http"
	"strings"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func (s *Service) registerOrganizationRoutes(router *corehttp.Router) {
	router.Get("/v1/organizations", s.handleListOrganizations)
	router.Get("/v1/organizations/:orgId", s.handleGetOrganization)
	router.Post("/v1/organizations", s.handleCreateOrganization)
	router.Patch("/v1/organizations/:orgId", s.handlePatchOrganization)
	router.Delete("/v1/organizations/:orgId", s.handleDeleteOrganization)
	router.Patch("/v1/organizations/:orgId/metadata", s.handlePatchOrganizationMetadata)
}

func (s *Service) handleListOrganizations(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	limit, offset := parsePagination(c)
	query := strings.ToLower(c.Query("query"))
	orgs := sortNewestFirst(s.store.Organizations.All())
	filtered := make([]corestore.Record, 0, len(orgs))
	for _, org := range orgs {
		if query != "" &&
			!strings.Contains(strings.ToLower(stringField(org, "name")), query) &&
			!strings.Contains(strings.ToLower(stringField(org, "slug")), query) {
			continue
		}
		filtered = append(filtered, org)
	}
	paged := sliceRecords(filtered, limit, offset)
	data := make([]map[string]any, 0, len(paged))
	for _, org := range paged {
		data = append(data, organizationResponse(org))
	}
	c.JSON(http.StatusOK, paginatedResponse(data, len(filtered), limit, offset))
}

func (s *Service) handleGetOrganization(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	org := s.findOrg(c.Param("orgId"))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	c.JSON(http.StatusOK, organizationResponse(org))
}

func (s *Service) handleCreateOrganization(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	body := readJSONBody(c.Request)
	name := stringValue(body["name"])
	if name == "" {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "name is required")
		return
	}
	now := nowUnix()
	slug := firstNonEmpty(stringValue(body["slug"]), slugify(name))
	org := s.store.Organizations.Insert(corestore.Record{
		"clerk_id":                  clerkID("org_"),
		"name":                      name,
		"slug":                      slug,
		"image_url":                 nil,
		"has_logo":                  false,
		"members_count":             0,
		"pending_invitations_count": 0,
		"public_metadata":           mapValue(body["public_metadata"]),
		"private_metadata":          mapValue(body["private_metadata"]),
		"max_allowed_memberships":   numberOrNil(body["max_allowed_memberships"]),
		"admin_delete_enabled":      boolOrDefault(body["admin_delete_enabled"], true),
		"created_at_unix":           now,
		"updated_at_unix":           now,
	})
	if createdBy := stringValue(body["created_by"]); createdBy != "" {
		user := firstRecord(s.store.Users.FindBy("clerk_id", createdBy))
		if user != nil {
			s.store.Memberships.Insert(corestore.Record{
				"membership_id":    clerkID("orgmem_"),
				"org_id":           stringField(org, "clerk_id"),
				"user_id":          createdBy,
				"role":             "org:admin",
				"permissions":      defaultPermissions("org:admin"),
				"public_metadata":  map[string]any{},
				"private_metadata": map[string]any{},
				"created_at_unix":  now,
				"updated_at_unix":  now,
			})
			s.store.Organizations.Update(intField(org, "id"), corestore.Record{"members_count": 1})
			org = firstRecord(s.store.Organizations.FindBy("clerk_id", stringField(org, "clerk_id")))
		}
	}
	c.JSON(http.StatusOK, organizationResponse(org))
}

func (s *Service) handlePatchOrganization(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	body := readJSONBody(c.Request)
	patch := corestore.Record{"updated_at_unix": nowUnix()}
	assignStringPatch(patch, body, "name")
	assignStringPatch(patch, body, "slug")
	if body["public_metadata"] != nil {
		patch["public_metadata"] = mapValue(body["public_metadata"])
	}
	if body["private_metadata"] != nil {
		patch["private_metadata"] = mapValue(body["private_metadata"])
	}
	if _, ok := body["max_allowed_memberships"]; ok {
		patch["max_allowed_memberships"] = numberOrNil(body["max_allowed_memberships"])
	}
	if _, ok := body["admin_delete_enabled"]; ok {
		patch["admin_delete_enabled"] = boolValue(body["admin_delete_enabled"])
	}
	s.store.Organizations.Update(intField(org, "id"), patch)
	updated := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	c.JSON(http.StatusOK, organizationResponse(updated))
}

func (s *Service) handleDeleteOrganization(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	for _, membership := range s.store.Memberships.FindBy("org_id", orgID) {
		s.store.Memberships.Delete(intField(membership, "id"))
	}
	for _, invitation := range s.store.Invitations.FindBy("org_id", orgID) {
		s.store.Invitations.Delete(intField(invitation, "id"))
	}
	s.store.Organizations.Delete(intField(org, "id"))
	c.JSON(http.StatusOK, deletedResponse(orgID))
}

func (s *Service) handlePatchOrganizationMetadata(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	body := readJSONBody(c.Request)
	patch := corestore.Record{"updated_at_unix": nowUnix()}
	if body["public_metadata"] != nil {
		patch["public_metadata"] = mergeMaps(mapValue(org["public_metadata"]), mapValue(body["public_metadata"]))
	}
	if body["private_metadata"] != nil {
		patch["private_metadata"] = mergeMaps(mapValue(org["private_metadata"]), mapValue(body["private_metadata"]))
	}
	s.store.Organizations.Update(intField(org, "id"), patch)
	updated := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	c.JSON(http.StatusOK, organizationResponse(updated))
}

func (s *Service) findOrg(ref string) corestore.Record {
	if org := firstRecord(s.store.Organizations.FindBy("clerk_id", ref)); org != nil {
		return org
	}
	return firstRecord(s.store.Organizations.FindBy("slug", ref))
}

func boolOrDefault(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return boolValue(value)
}

func numberOrNil(value any) any {
	if value == nil {
		return nil
	}
	return intValue(value)
}
