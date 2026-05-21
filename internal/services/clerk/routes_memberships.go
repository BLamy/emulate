package clerk

import (
	"net/http"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func (s *Service) registerMembershipRoutes(router *corehttp.Router) {
	router.Get("/v1/organizations/:orgId/memberships", s.handleListMemberships)
	router.Post("/v1/organizations/:orgId/memberships", s.handleCreateMembership)
	router.Patch("/v1/organizations/:orgId/memberships/:userId", s.handlePatchMembership)
	router.Delete("/v1/organizations/:orgId/memberships/:userId", s.handleDeleteMembership)
	router.Patch("/v1/organizations/:orgId/memberships/:userId/metadata", s.handlePatchMembershipMetadata)
}

func (s *Service) handleListMemberships(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	limit, offset := parsePagination(c)
	role := c.Query("role")
	memberships := s.store.Memberships.FindBy("org_id", orgID)
	filtered := make([]corestore.Record, 0, len(memberships))
	for _, membership := range memberships {
		if role != "" && stringField(membership, "role") != role {
			continue
		}
		filtered = append(filtered, membership)
	}
	paged := sliceRecords(filtered, limit, offset)
	data := make([]map[string]any, 0, len(paged))
	for _, membership := range paged {
		user := firstRecord(s.store.Users.FindBy("clerk_id", stringField(membership, "user_id")))
		emails := []corestore.Record{}
		if user != nil {
			emails = s.store.EmailAddresses.FindBy("user_id", stringField(user, "clerk_id"))
		}
		data = append(data, membershipResponse(membership, org, user, emails))
	}
	c.JSON(http.StatusOK, paginatedResponse(data, len(filtered), limit, offset))
}

func (s *Service) handleCreateMembership(c *corehttp.Context) {
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
	userID := stringValue(body["user_id"])
	if userID == "" {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "user_id is required")
		return
	}
	user := firstRecord(s.store.Users.FindBy("clerk_id", userID))
	if user == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "User not found")
		return
	}
	if membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID) != nil {
		clerkError(c, http.StatusUnprocessableEntity, "DUPLICATE_RECORD", "User is already a member of this organization")
		return
	}
	role := firstNonEmpty(stringValue(body["role"]), "org:member")
	now := nowUnix()
	membership := s.store.Memberships.Insert(corestore.Record{
		"membership_id":    clerkID("orgmem_"),
		"org_id":           orgID,
		"user_id":          userID,
		"role":             role,
		"permissions":      defaultPermissions(role),
		"public_metadata":  map[string]any{},
		"private_metadata": map[string]any{},
		"created_at_unix":  now,
		"updated_at_unix":  now,
	})
	s.store.Organizations.Update(intField(org, "id"), corestore.Record{"members_count": intField(org, "members_count") + 1, "updated_at_unix": now})
	updatedOrg := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	emails := s.store.EmailAddresses.FindBy("user_id", userID)
	c.JSON(http.StatusOK, membershipResponse(membership, updatedOrg, user, emails))
}

func (s *Service) handlePatchMembership(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	userID := c.Param("userId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	membership := membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID)
	if membership == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Membership not found")
		return
	}
	body := readJSONBody(c.Request)
	patch := corestore.Record{"updated_at_unix": nowUnix()}
	if body["role"] != nil {
		role := stringValue(body["role"])
		patch["role"] = role
		patch["permissions"] = defaultPermissions(role)
	}
	s.store.Memberships.Update(intField(membership, "id"), patch)
	updated := membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID)
	user := firstRecord(s.store.Users.FindBy("clerk_id", userID))
	emails := []corestore.Record{}
	if user != nil {
		emails = s.store.EmailAddresses.FindBy("user_id", userID)
	}
	c.JSON(http.StatusOK, membershipResponse(updated, org, user, emails))
}

func (s *Service) handleDeleteMembership(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	userID := c.Param("userId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	membership := membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID)
	if membership == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Membership not found")
		return
	}
	s.store.Memberships.Delete(intField(membership, "id"))
	s.store.Organizations.Update(intField(org, "id"), corestore.Record{"members_count": max(0, intField(org, "members_count")-1), "updated_at_unix": nowUnix()})
	c.JSON(http.StatusOK, deletedResponse(stringField(membership, "membership_id")))
}

func (s *Service) handlePatchMembershipMetadata(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	userID := c.Param("userId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	membership := membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID)
	if membership == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Membership not found")
		return
	}
	body := readJSONBody(c.Request)
	patch := corestore.Record{"updated_at_unix": nowUnix()}
	if body["public_metadata"] != nil {
		patch["public_metadata"] = mergeMaps(mapValue(membership["public_metadata"]), mapValue(body["public_metadata"]))
	}
	if body["private_metadata"] != nil {
		patch["private_metadata"] = mergeMaps(mapValue(membership["private_metadata"]), mapValue(body["private_metadata"]))
	}
	s.store.Memberships.Update(intField(membership, "id"), patch)
	updated := membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID)
	user := firstRecord(s.store.Users.FindBy("clerk_id", userID))
	emails := []corestore.Record{}
	if user != nil {
		emails = s.store.EmailAddresses.FindBy("user_id", userID)
	}
	c.JSON(http.StatusOK, membershipResponse(updated, org, user, emails))
}

func membershipForUser(memberships []corestore.Record, userID string) corestore.Record {
	for _, membership := range memberships {
		if stringField(membership, "user_id") == userID {
			return membership
		}
	}
	return nil
}

func defaultPermissions(role string) []string {
	if role == "org:admin" {
		return []string{
			"org:sys_profile:manage",
			"org:sys_profile:delete",
			"org:sys_memberships:read",
			"org:sys_memberships:manage",
			"org:sys_domains:read",
			"org:sys_domains:manage",
		}
	}
	return []string{"org:sys_memberships:read"}
}
