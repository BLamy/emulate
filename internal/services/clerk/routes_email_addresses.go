package clerk

import (
	"net/http"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func (s *Service) registerEmailAddressRoutes(router *corehttp.Router) {
	router.Get("/v1/email_addresses/:emailId", s.handleGetEmailAddress)
	router.Post("/v1/email_addresses", s.handleCreateEmailAddress)
	router.Patch("/v1/email_addresses/:emailId", s.handlePatchEmailAddress)
	router.Delete("/v1/email_addresses/:emailId", s.handleDeleteEmailAddress)
}

func (s *Service) handleGetEmailAddress(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	email := firstRecord(s.store.EmailAddresses.FindBy("email_id", c.Param("emailId")))
	if email == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Email address not found")
		return
	}
	c.JSON(http.StatusOK, emailAddressResponse(email))
}

func (s *Service) handleCreateEmailAddress(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	body := readJSONBody(c.Request)
	userID := stringValue(body["user_id"])
	emailAddress := stringValue(body["email_address"])
	if userID == "" || emailAddress == "" {
		clerkError(c, http.StatusUnprocessableEntity, "INVALID_REQUEST_BODY", "user_id and email_address are required")
		return
	}
	user := firstRecord(s.store.Users.FindBy("clerk_id", userID))
	if user == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "User not found")
		return
	}
	now := nowUnix()
	primary := boolValue(body["primary"])
	email := s.store.EmailAddresses.Insert(corestore.Record{
		"email_id":              clerkID("idn_"),
		"email_address":         emailAddress,
		"user_id":               userID,
		"verification_status":   verificationStatus(boolValue(body["verified"])),
		"verification_strategy": "email_code",
		"is_primary":            primary,
		"reserved":              false,
		"created_at_unix":       now,
		"updated_at_unix":       now,
	})
	if primary {
		s.makePrimaryEmail(user, email)
	}
	c.JSON(http.StatusOK, emailAddressResponse(email))
}

func (s *Service) handlePatchEmailAddress(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	emailID := c.Param("emailId")
	email := firstRecord(s.store.EmailAddresses.FindBy("email_id", emailID))
	if email == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Email address not found")
		return
	}
	body := readJSONBody(c.Request)
	patch := corestore.Record{"updated_at_unix": nowUnix()}
	if _, ok := body["verified"]; ok {
		patch["verification_status"] = verificationStatus(boolValue(body["verified"]))
	}
	if boolValue(body["primary"]) {
		patch["is_primary"] = true
		user := firstRecord(s.store.Users.FindBy("clerk_id", stringField(email, "user_id")))
		if user != nil {
			s.makePrimaryEmail(user, email)
		}
	}
	s.store.EmailAddresses.Update(intField(email, "id"), patch)
	updated := firstRecord(s.store.EmailAddresses.FindBy("email_id", emailID))
	c.JSON(http.StatusOK, emailAddressResponse(updated))
}

func (s *Service) handleDeleteEmailAddress(c *corehttp.Context) {
	if !requireSecretKey(c) {
		return
	}
	emailID := c.Param("emailId")
	email := firstRecord(s.store.EmailAddresses.FindBy("email_id", emailID))
	if email == nil {
		clerkError(c, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Email address not found")
		return
	}
	s.store.EmailAddresses.Delete(intField(email, "id"))
	if boolField(email, "is_primary") {
		remaining := s.store.EmailAddresses.FindBy("user_id", stringField(email, "user_id"))
		user := firstRecord(s.store.Users.FindBy("clerk_id", stringField(email, "user_id")))
		if user != nil {
			if next := firstRecord(remaining); next != nil {
				s.store.EmailAddresses.Update(intField(next, "id"), corestore.Record{"is_primary": true})
				s.store.Users.Update(intField(user, "id"), corestore.Record{"primary_email_address_id": stringField(next, "email_id")})
			} else {
				s.store.Users.Update(intField(user, "id"), corestore.Record{"primary_email_address_id": nil})
			}
		}
	}
	c.JSON(http.StatusOK, deletedResponse(emailID))
}

func (s *Service) makePrimaryEmail(user corestore.Record, email corestore.Record) {
	userID := stringField(user, "clerk_id")
	emailID := stringField(email, "email_id")
	for _, existing := range s.store.EmailAddresses.FindBy("user_id", userID) {
		if stringField(existing, "email_id") != emailID && boolField(existing, "is_primary") {
			s.store.EmailAddresses.Update(intField(existing, "id"), corestore.Record{"is_primary": false})
		}
	}
	s.store.Users.Update(intField(user, "id"), corestore.Record{"primary_email_address_id": emailID, "updated_at_unix": nowUnix()})
}

func verificationStatus(verified bool) string {
	if verified {
		return "verified"
	}
	return "unverified"
}
