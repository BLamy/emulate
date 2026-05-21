package clerk

import (
	"net/http"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func (s *Service) registerInvitationRoutes(router *corehttp.Router) {
	router.Get("/v1/organizations/:orgId/invitations", s.handleListInvitations)
	router.Get("/v1/organizations/:orgId/invitations/:invitationId", s.handleGetInvitation)
	router.Post("/v1/organizations/:orgId/invitations", s.handleCreateInvitation)
	router.Post("/v1/organizations/:orgId/invitations/bulk", s.handleCreateBulkInvitations)
	router.Post("/v1/organizations/:orgId/invitations/:invitationId/revoke", s.handleRevokeInvitation)
}

func (s *Service) handleListInvitations(c *corehttp.Context) {
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
	status := c.Query("status")
	invitations := s.store.Invitations.FindBy("org_id", orgID)
	filtered := make([]corestore.Record, 0, len(invitations))
	for _, invitation := range invitations {
		if status != "" && stringField(invitation, "status") != status {
			continue
		}
		filtered = append(filtered, invitation)
	}
	paged := sliceRecords(filtered, limit, offset)
	data := make([]map[string]any, 0, len(paged))
	for _, invitation := range paged {
		data = append(data, invitationResponse(invitation))
	}
	c.JSON(http.StatusOK, paginatedResponse(data, len(filtered), limit, offset))
}

func (s *Service) handleGetInvitation(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	invitation := firstRecord(s.store.Invitations.FindBy("invitation_id", c.Param("invitationId")))
	if invitation == nil || stringField(invitation, "org_id") != orgID {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Invitation not found")
		return
	}
	c.JSON(http.StatusOK, invitationResponse(invitation))
}

func (s *Service) handleCreateInvitation(c *corehttp.Context) {
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
	emailAddress := stringValue(body["email_address"])
	if emailAddress == "" {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "email_address is required")
		return
	}
	invitation := s.createInvitation(org, emailAddress, firstNonEmpty(stringValue(body["role"]), "org:member"), expiresInDays(body["expires_in_days"]))
	c.JSON(http.StatusOK, invitationResponse(invitation))
}

func (s *Service) handleCreateBulkInvitations(c *corehttp.Context) {
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
	emailAddresses := stringSliceValue(body["email_addresses"])
	if len(emailAddresses) == 0 {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "email_addresses array is required")
		return
	}
	role := firstNonEmpty(stringValue(body["role"]), "org:member")
	expires := expiresInDays(body["expires_in_days"])
	data := make([]map[string]any, 0, len(emailAddresses))
	for _, emailAddress := range emailAddresses {
		data = append(data, invitationResponse(s.createInvitation(org, emailAddress, role, expires)))
	}
	c.JSON(http.StatusOK, data)
}

func (s *Service) handleRevokeInvitation(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	orgID := c.Param("orgId")
	org := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID))
	if org == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Organization not found")
		return
	}
	invitation := firstRecord(s.store.Invitations.FindBy("invitation_id", c.Param("invitationId")))
	if invitation == nil || stringField(invitation, "org_id") != orgID {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Invitation not found")
		return
	}
	if stringField(invitation, "status") != "pending" {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "Only pending invitations can be revoked")
		return
	}
	now := nowUnix()
	s.store.Invitations.Update(intField(invitation, "id"), corestore.Record{"status": "revoked", "updated_at_unix": now})
	s.store.Organizations.Update(intField(org, "id"), corestore.Record{"pending_invitations_count": max(0, intField(org, "pending_invitations_count")-1), "updated_at_unix": now})
	updated := firstRecord(s.store.Invitations.FindBy("invitation_id", c.Param("invitationId")))
	c.JSON(http.StatusOK, invitationResponse(updated))
}

func (s *Service) createInvitation(org corestore.Record, emailAddress string, role string, expiresDays int) corestore.Record {
	now := nowUnix()
	orgID := stringField(org, "clerk_id")
	invitation := s.store.Invitations.Insert(corestore.Record{
		"invitation_id":   clerkID("orginv_"),
		"email_address":   emailAddress,
		"org_id":          orgID,
		"role":            role,
		"status":          "pending",
		"expires_at":      now + int64(expiresDays)*86400,
		"created_at_unix": now,
		"updated_at_unix": now,
	})
	if latest := firstRecord(s.store.Organizations.FindBy("clerk_id", orgID)); latest != nil {
		org = latest
	}
	s.store.Organizations.Update(intField(org, "id"), corestore.Record{
		"pending_invitations_count": intField(org, "pending_invitations_count") + 1,
		"updated_at_unix":           now,
	})
	return invitation
}

func expiresInDays(value any) int {
	days := intValue(value)
	if days <= 0 {
		return 30
	}
	return days
}
