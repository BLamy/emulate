package clerk

import (
	"strings"

	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func userResponse(user corestore.Record, emailAddresses []corestore.Record) map[string]any {
	imageURL := stringField(user, "image_url")
	if imageURL == "" {
		imageURL = "https://img.clerk.com/preview?seed=" + stringField(user, "clerk_id")
	}
	profileImageURL := stringField(user, "profile_image_url")
	if profileImageURL == "" {
		profileImageURL = "https://img.clerk.com/preview?seed=" + stringField(user, "clerk_id")
	}
	emails := make([]map[string]any, 0, len(emailAddresses))
	for _, email := range emailAddresses {
		emails = append(emails, emailAddressResponse(email))
	}
	return map[string]any{
		"id":                       stringField(user, "clerk_id"),
		"object":                   "user",
		"username":                 nilString(user, "username"),
		"first_name":               nilString(user, "first_name"),
		"last_name":                nilString(user, "last_name"),
		"image_url":                imageURL,
		"profile_image_url":        profileImageURL,
		"has_image":                stringField(user, "image_url") != "",
		"primary_email_address_id": nilString(user, "primary_email_address_id"),
		"primary_phone_number_id":  nilString(user, "primary_phone_number_id"),
		"primary_web3_wallet_id":   nil,
		"email_addresses":          emails,
		"phone_numbers":            []any{},
		"web3_wallets":             []any{},
		"external_accounts":        []any{},
		"saml_accounts":            []any{},
		"passkeys":                 []any{},
		"password_enabled":         boolField(user, "password_enabled"),
		"totp_enabled":             boolField(user, "totp_enabled"),
		"backup_code_enabled":      boolField(user, "backup_code_enabled"),
		"two_factor_enabled":       boolField(user, "two_factor_enabled"),
		"banned":                   boolField(user, "banned"),
		"locked":                   boolField(user, "locked"),
		"external_id":              nilString(user, "external_id"),
		"public_metadata":          mapValue(user["public_metadata"]),
		"private_metadata":         mapValue(user["private_metadata"]),
		"unsafe_metadata":          mapValue(user["unsafe_metadata"]),
		"last_sign_in_at":          nilInt64(user, "last_sign_in_at"),
		"last_active_at":           nilInt64(user, "last_active_at"),
		"created_at":               int64Field(user, "created_at_unix"),
		"updated_at":               int64Field(user, "updated_at_unix"),
	}
}

func emailAddressResponse(email corestore.Record) map[string]any {
	return map[string]any{
		"id":            stringField(email, "email_id"),
		"object":        "email_address",
		"email_address": stringField(email, "email_address"),
		"reserved":      boolField(email, "reserved"),
		"verification": map[string]any{
			"status":   stringField(email, "verification_status"),
			"strategy": stringField(email, "verification_strategy"),
		},
		"linked_to":  []any{},
		"created_at": int64Field(email, "created_at_unix"),
		"updated_at": int64Field(email, "updated_at_unix"),
	}
}

func organizationResponse(org corestore.Record) map[string]any {
	return map[string]any{
		"id":                        stringField(org, "clerk_id"),
		"object":                    "organization",
		"name":                      stringField(org, "name"),
		"slug":                      stringField(org, "slug"),
		"image_url":                 nilString(org, "image_url"),
		"has_image":                 stringField(org, "image_url") != "",
		"members_count":             intField(org, "members_count"),
		"pending_invitations_count": intField(org, "pending_invitations_count"),
		"max_allowed_memberships":   nilInt(org, "max_allowed_memberships"),
		"admin_delete_enabled":      boolField(org, "admin_delete_enabled"),
		"public_metadata":           mapValue(org["public_metadata"]),
		"private_metadata":          mapValue(org["private_metadata"]),
		"created_at":                int64Field(org, "created_at_unix"),
		"updated_at":                int64Field(org, "updated_at_unix"),
	}
}

func membershipResponse(membership corestore.Record, org corestore.Record, user corestore.Record, emailAddresses []corestore.Record) map[string]any {
	var organization any
	if org != nil {
		organization = organizationResponse(org)
	}
	var publicUserData any
	if user != nil {
		identifier := stringField(user, "username")
		for _, email := range emailAddresses {
			if boolField(email, "is_primary") {
				identifier = stringField(email, "email_address")
				break
			}
		}
		if identifier == "" && len(emailAddresses) > 0 {
			identifier = stringField(emailAddresses[0], "email_address")
		}
		if identifier == "" {
			identifier = stringField(user, "clerk_id")
		}
		publicUserData = map[string]any{
			"user_id":    stringField(user, "clerk_id"),
			"first_name": nilString(user, "first_name"),
			"last_name":  nilString(user, "last_name"),
			"image_url":  nilString(user, "image_url"),
			"has_image":  stringField(user, "image_url") != "",
			"identifier": identifier,
		}
	}
	return map[string]any{
		"id":               stringField(membership, "membership_id"),
		"object":           "organization_membership",
		"role":             stringField(membership, "role"),
		"permissions":      stringSliceValue(membership["permissions"]),
		"public_metadata":  mapValue(membership["public_metadata"]),
		"private_metadata": mapValue(membership["private_metadata"]),
		"organization":     organization,
		"public_user_data": publicUserData,
		"created_at":       int64Field(membership, "created_at_unix"),
		"updated_at":       int64Field(membership, "updated_at_unix"),
	}
}

func invitationResponse(invitation corestore.Record) map[string]any {
	return map[string]any{
		"id":              stringField(invitation, "invitation_id"),
		"object":          "organization_invitation",
		"email_address":   stringField(invitation, "email_address"),
		"role":            stringField(invitation, "role"),
		"status":          stringField(invitation, "status"),
		"organization_id": stringField(invitation, "org_id"),
		"created_at":      int64Field(invitation, "created_at_unix"),
		"updated_at":      int64Field(invitation, "updated_at_unix"),
	}
}

func sessionResponse(session corestore.Record) map[string]any {
	return map[string]any{
		"id":             stringField(session, "clerk_id"),
		"object":         "session",
		"user_id":        stringField(session, "user_id"),
		"client_id":      stringField(session, "client_id"),
		"status":         stringField(session, "status"),
		"last_active_at": nilInt64(session, "last_active_at"),
		"expire_at":      int64Field(session, "expire_at"),
		"abandon_at":     int64Field(session, "abandon_at"),
		"created_at":     int64Field(session, "created_at_unix"),
		"updated_at":     int64Field(session, "updated_at_unix"),
	}
}

func nilString(record corestore.Record, field string) any {
	value := stringField(record, field)
	if value == "" {
		return nil
	}
	return value
}

func nilInt(record corestore.Record, field string) any {
	if record == nil || record[field] == nil {
		return nil
	}
	return intValue(record[field])
}

func nilInt64(record corestore.Record, field string) any {
	if record == nil || record[field] == nil {
		return nil
	}
	return int64Value(record[field])
}

func userDisplayName(user corestore.Record) string {
	name := strings.TrimSpace(stringField(user, "first_name") + " " + stringField(user, "last_name"))
	if name != "" {
		return name
	}
	if username := stringField(user, "username"); username != "" {
		return username
	}
	return "User"
}
