package clerk

import (
	"strings"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

const serviceLabel = "Clerk"

type Options struct {
	Store   *corestore.Store
	BaseURL string
	Seed    *SeedConfig
}

type SeedConfig struct {
	Users             []UserSeed             `json:"users"`
	Organizations     []OrganizationSeed     `json:"organizations"`
	OAuthApplications []OAuthApplicationSeed `json:"oauth_applications"`
}

type UserSeed struct {
	ClerkID         string         `json:"clerk_id"`
	EmailAddresses  []string       `json:"email_addresses"`
	FirstName       string         `json:"first_name"`
	LastName        string         `json:"last_name"`
	Username        string         `json:"username"`
	Password        string         `json:"password"`
	ExternalID      string         `json:"external_id"`
	PublicMetadata  map[string]any `json:"public_metadata"`
	PrivateMetadata map[string]any `json:"private_metadata"`
	UnsafeMetadata  map[string]any `json:"unsafe_metadata"`
}

type OrganizationSeed struct {
	ClerkID               string             `json:"clerk_id"`
	Name                  string             `json:"name"`
	Slug                  string             `json:"slug"`
	MaxAllowedMemberships *int               `json:"max_allowed_memberships"`
	PublicMetadata        map[string]any     `json:"public_metadata"`
	PrivateMetadata       map[string]any     `json:"private_metadata"`
	Members               []OrganizationUser `json:"members"`
}

type OrganizationUser struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type OAuthApplicationSeed struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Public       bool     `json:"public"`
}

type Service struct {
	store   Store
	baseURL string
}

func Register(router *corehttp.Router, options Options) {
	service := New(options)
	service.RegisterRoutes(router)
}

func New(options Options) *Service {
	runtimeStore := options.Store
	if runtimeStore == nil {
		runtimeStore = corestore.New()
	}
	baseURL := strings.TrimRight(options.BaseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:4000"
	}
	service := &Service{store: NewStore(runtimeStore), baseURL: baseURL}
	service.SeedDefaults()
	if options.Seed != nil {
		service.SeedFromConfig(*options.Seed)
	}
	return service
}

func SeedFromConfig(runtimeStore *corestore.Store, baseURL string, config SeedConfig) {
	New(Options{Store: runtimeStore, BaseURL: baseURL, Seed: &config})
}

func (s *Service) RegisterRoutes(router *corehttp.Router) {
	s.registerOAuthRoutes(router)
	s.registerUserRoutes(router)
	s.registerEmailAddressRoutes(router)
	s.registerOrganizationRoutes(router)
	s.registerMembershipRoutes(router)
	s.registerInvitationRoutes(router)
	s.registerSessionRoutes(router)
}

func (s *Service) SeedDefaults() {
	if s.store.Users.Count() > 0 {
		return
	}
	user := s.store.Users.Insert(defaultUser("test_password"))
	email := s.store.EmailAddresses.Insert(defaultEmailAddress(stringField(user, "clerk_id"), "test@example.com", true))
	s.store.Users.Update(intField(user, "id"), corestore.Record{"primary_email_address_id": stringField(email, "email_id")})
	if firstRecord(s.store.OAuthApps.FindBy("client_id", "clerk_emulate_client")) == nil {
		now := nowUnix()
		s.store.OAuthApps.Insert(corestore.Record{
			"app_id":          clerkID("oauth_app_"),
			"name":            "Emulate App",
			"client_id":       "clerk_emulate_client",
			"client_secret":   "clerk_emulate_secret",
			"is_public":       false,
			"scopes":          []string{"openid", "profile", "email"},
			"redirect_uris":   []string{"http://localhost:3000/api/auth/callback/clerk"},
			"created_at_unix": now,
			"updated_at_unix": now,
		})
	}
}

func (s *Service) SeedFromConfig(config SeedConfig) {
	for _, seed := range config.Users {
		existingEmail := ""
		if len(seed.EmailAddresses) > 0 {
			existingEmail = seed.EmailAddresses[0]
		}
		if existingEmail != "" && firstRecord(s.store.EmailAddresses.FindBy("email_address", existingEmail)) != nil {
			continue
		}
		clerkIDValue := seed.ClerkID
		if clerkIDValue == "" {
			clerkIDValue = clerkID("user_")
		}
		firstName := firstNonEmpty(seed.FirstName, "Test")
		lastName := firstNonEmpty(seed.LastName, "User")
		now := nowUnix()
		user := s.store.Users.Insert(corestore.Record{
			"clerk_id":                 clerkIDValue,
			"username":                 nilStringValue(seed.Username),
			"first_name":               firstName,
			"last_name":                lastName,
			"image_url":                nil,
			"profile_image_url":        nil,
			"external_id":              nilStringValue(seed.ExternalID),
			"primary_email_address_id": nil,
			"primary_phone_number_id":  nil,
			"password_enabled":         seed.Password != "",
			"password_hash":            nilStringValue(seed.Password),
			"totp_enabled":             false,
			"backup_code_enabled":      false,
			"two_factor_enabled":       false,
			"banned":                   false,
			"locked":                   false,
			"public_metadata":          cloneMap(seed.PublicMetadata),
			"private_metadata":         cloneMap(seed.PrivateMetadata),
			"unsafe_metadata":          cloneMap(seed.UnsafeMetadata),
			"last_active_at":           nil,
			"last_sign_in_at":          nil,
			"created_at_unix":          now,
			"updated_at_unix":          now,
		})
		primaryEmailID := ""
		for index, emailAddress := range seed.EmailAddresses {
			email := s.store.EmailAddresses.Insert(defaultEmailAddress(clerkIDValue, emailAddress, index == 0))
			if index == 0 {
				primaryEmailID = stringField(email, "email_id")
			}
		}
		if primaryEmailID != "" {
			s.store.Users.Update(intField(user, "id"), corestore.Record{"primary_email_address_id": primaryEmailID})
		}
	}

	for _, seed := range config.Organizations {
		name := seed.Name
		if name == "" {
			continue
		}
		slug := seed.Slug
		if slug == "" {
			slug = slugify(name)
		}
		if firstRecord(s.store.Organizations.FindBy("slug", slug)) != nil {
			continue
		}
		orgID := seed.ClerkID
		if orgID == "" {
			orgID = clerkID("org_")
		}
		now := nowUnix()
		maxAllowed := any(nil)
		if seed.MaxAllowedMemberships != nil {
			maxAllowed = *seed.MaxAllowedMemberships
		}
		org := s.store.Organizations.Insert(corestore.Record{
			"clerk_id":                  orgID,
			"name":                      name,
			"slug":                      slug,
			"image_url":                 nil,
			"has_logo":                  false,
			"members_count":             0,
			"pending_invitations_count": 0,
			"public_metadata":           cloneMap(seed.PublicMetadata),
			"private_metadata":          cloneMap(seed.PrivateMetadata),
			"max_allowed_memberships":   maxAllowed,
			"admin_delete_enabled":      true,
			"created_at_unix":           now,
			"updated_at_unix":           now,
		})
		memberCount := 0
		for _, member := range seed.Members {
			email := firstRecord(s.store.EmailAddresses.FindBy("email_address", member.Email))
			if email == nil {
				continue
			}
			user := firstRecord(s.store.Users.FindBy("clerk_id", stringField(email, "user_id")))
			if user == nil {
				continue
			}
			userID := stringField(user, "clerk_id")
			if membershipForUser(s.store.Memberships.FindBy("org_id", orgID), userID) != nil {
				continue
			}
			role := normalizeOrgRole(member.Role)
			s.store.Memberships.Insert(corestore.Record{
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
			memberCount++
		}
		if memberCount > 0 {
			s.store.Organizations.Update(intField(org, "id"), corestore.Record{"members_count": memberCount})
		}
	}

	for _, seed := range config.OAuthApplications {
		if seed.ClientID == "" || firstRecord(s.store.OAuthApps.FindBy("client_id", seed.ClientID)) != nil {
			continue
		}
		scopes := seed.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		now := nowUnix()
		s.store.OAuthApps.Insert(corestore.Record{
			"app_id":          clerkID("oauth_app_"),
			"name":            seed.Name,
			"client_id":       seed.ClientID,
			"client_secret":   seed.ClientSecret,
			"is_public":       seed.Public,
			"scopes":          scopes,
			"redirect_uris":   seed.RedirectURIs,
			"created_at_unix": now,
			"updated_at_unix": now,
		})
	}
}

func defaultUser(password string) corestore.Record {
	now := nowUnix()
	return corestore.Record{
		"clerk_id":                 clerkID("user_"),
		"username":                 nil,
		"first_name":               "Test",
		"last_name":                "User",
		"image_url":                nil,
		"profile_image_url":        nil,
		"external_id":              nil,
		"primary_email_address_id": nil,
		"primary_phone_number_id":  nil,
		"password_enabled":         password != "",
		"password_hash":            nilStringValue(password),
		"totp_enabled":             false,
		"backup_code_enabled":      false,
		"two_factor_enabled":       false,
		"banned":                   false,
		"locked":                   false,
		"public_metadata":          map[string]any{},
		"private_metadata":         map[string]any{},
		"unsafe_metadata":          map[string]any{},
		"last_active_at":           nil,
		"last_sign_in_at":          nil,
		"created_at_unix":          now,
		"updated_at_unix":          now,
	}
}

func defaultEmailAddress(userID string, emailAddress string, primary bool) corestore.Record {
	now := nowUnix()
	return corestore.Record{
		"email_id":              clerkID("idn_"),
		"email_address":         emailAddress,
		"user_id":               userID,
		"verification_status":   "verified",
		"verification_strategy": "email_code",
		"is_primary":            primary,
		"reserved":              false,
		"created_at_unix":       now,
		"updated_at_unix":       now,
	}
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func nilStringValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func normalizeOrgRole(role string) string {
	if role == "" {
		return "org:member"
	}
	if strings.HasPrefix(role, "org:") {
		return role
	}
	return "org:" + role
}
