package clerk

import (
	"net/http"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func (s *Service) registerSessionRoutes(router *corehttp.Router) {
	router.Get("/v1/sessions", s.handleListSessions)
	router.Get("/v1/sessions/:sessionId", s.handleGetSession)
	router.Post("/v1/sessions", s.handleCreateSession)
	router.Post("/v1/sessions/:sessionId/revoke", s.handleRevokeSession)
	router.Post("/v1/sessions/:sessionId/tokens", s.handleCreateSessionToken)
	router.Post("/v1/sessions/:sessionId/tokens/:template", s.handleCreateSessionToken)
}

func (s *Service) handleListSessions(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	limit, offset := parsePagination(c)
	userID := c.Query("user_id")
	sessions := sortNewestFirst(s.store.Sessions.All())
	filtered := make([]corestore.Record, 0, len(sessions))
	for _, session := range sessions {
		if userID != "" && stringField(session, "user_id") != userID {
			continue
		}
		filtered = append(filtered, session)
	}
	paged := sliceRecords(filtered, limit, offset)
	data := make([]map[string]any, 0, len(paged))
	for _, session := range paged {
		data = append(data, sessionResponse(session))
	}
	c.JSON(http.StatusOK, paginatedResponse(data, len(filtered), limit, offset))
}

func (s *Service) handleGetSession(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	session := firstRecord(s.store.Sessions.FindBy("clerk_id", c.Param("sessionId")))
	if session == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Session not found")
		return
	}
	c.JSON(http.StatusOK, sessionResponse(session))
}

func (s *Service) handleCreateSession(c *corehttp.Context) {
	if !requireSecretKey(c) {
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
	now := nowUnix()
	session := s.store.Sessions.Insert(corestore.Record{
		"clerk_id":        clerkID("sess_"),
		"user_id":         userID,
		"client_id":       firstNonEmpty(stringValue(body["client_id"]), "client_emulate"),
		"status":          "active",
		"last_active_at":  now,
		"expire_at":       now + 86400,
		"abandon_at":      now + 604800,
		"created_at_unix": now,
		"updated_at_unix": now,
	})
	s.store.Users.Update(intField(user, "id"), corestore.Record{"last_active_at": now, "last_sign_in_at": now, "updated_at_unix": now})
	c.JSON(http.StatusOK, sessionResponse(session))
}

func (s *Service) handleRevokeSession(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	sessionID := c.Param("sessionId")
	session := firstRecord(s.store.Sessions.FindBy("clerk_id", sessionID))
	if session == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Session not found")
		return
	}
	s.store.Sessions.Update(intField(session, "id"), corestore.Record{"status": "revoked", "updated_at_unix": nowUnix()})
	updated := firstRecord(s.store.Sessions.FindBy("clerk_id", sessionID))
	c.JSON(http.StatusOK, sessionResponse(updated))
}

func (s *Service) handleCreateSessionToken(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	sessionID := c.Param("sessionId")
	session := firstRecord(s.store.Sessions.FindBy("clerk_id", sessionID))
	if session == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Session not found")
		return
	}
	if stringField(session, "status") != "active" {
		clerkError(c, http.StatusUnprocessableEntity, "SESSION_NOT_ACTIVE", "Session is not active")
		return
	}
	user := firstRecord(s.store.Users.FindBy("clerk_id", stringField(session, "user_id")))
	if user == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "User not found")
		return
	}
	var org corestore.Record
	var membership corestore.Record
	if c.Param("template") == "" {
		if memberships := s.store.Memberships.FindBy("user_id", stringField(user, "clerk_id")); len(memberships) > 0 {
			membership = memberships[0]
			org = firstRecord(s.store.Organizations.FindBy("clerk_id", stringField(membership, "org_id")))
		}
	}
	jwt, err := createSessionToken(user, sessionID, s.baseURL, org, membership)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]any{"message": "Failed to sign session token"})
		return
	}
	s.store.Sessions.Update(intField(session, "id"), corestore.Record{"last_active_at": nowUnix()})
	c.JSON(http.StatusOK, map[string]any{"object": "token", "jwt": jwt})
}
