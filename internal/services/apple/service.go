package apple

import (
	"strings"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

const serviceLabel = "Apple"

type Options struct {
	Store   *corestore.Store
	BaseURL string
	Seed    *SeedConfig
}

type SeedConfig struct {
	Port         int               `json:"port,omitempty"`
	Users        []UserSeed        `json:"users"`
	OAuthClients []OAuthClientSeed `json:"oauth_clients"`
}

type UserSeed struct {
	Email          string `json:"email"`
	Name           string `json:"name"`
	GivenName      string `json:"given_name"`
	FamilyName     string `json:"family_name"`
	IsPrivateEmail bool   `json:"is_private_email"`
}

type OAuthClientSeed struct {
	ClientID     string   `json:"client_id"`
	TeamID       string   `json:"team_id"`
	KeyID        string   `json:"key_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
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
	service := &Service{
		store:   NewStore(runtimeStore),
		baseURL: baseURL,
	}
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
}

func (s *Service) SeedDefaults() {
	if firstRecord(s.store.Users.FindBy("email", "testuser@icloud.com")) != nil {
		return
	}
	s.store.Users.Insert(corestore.Record{
		"uid":                 generateAppleUID(),
		"email":               "testuser@icloud.com",
		"name":                "Test User",
		"given_name":          "Test",
		"family_name":         "User",
		"email_verified":      true,
		"is_private_email":    false,
		"private_relay_email": nil,
		"real_user_status":    2,
	})
}

func (s *Service) SeedFromConfig(config SeedConfig) {
	for _, seed := range config.Users {
		email := strings.TrimSpace(seed.Email)
		if email == "" || firstRecord(s.store.Users.FindBy("email", email)) != nil {
			continue
		}
		name := seed.Name
		if name == "" {
			name = strings.Split(email, "@")[0]
		}
		nameParts := strings.Fields(name)
		givenName := seed.GivenName
		if givenName == "" && len(nameParts) > 0 {
			givenName = nameParts[0]
		}
		familyName := seed.FamilyName
		if familyName == "" && len(nameParts) > 1 {
			familyName = strings.Join(nameParts[1:], " ")
		}
		privateRelayEmail := any(nil)
		if seed.IsPrivateEmail {
			privateRelayEmail = generatePrivateRelayEmail()
		}
		s.store.Users.Insert(corestore.Record{
			"uid":                 generateAppleUID(),
			"email":               email,
			"name":                name,
			"given_name":          givenName,
			"family_name":         familyName,
			"email_verified":      true,
			"is_private_email":    seed.IsPrivateEmail,
			"private_relay_email": privateRelayEmail,
			"real_user_status":    2,
		})
	}

	for _, seed := range config.OAuthClients {
		clientID := strings.TrimSpace(seed.ClientID)
		if clientID == "" || firstRecord(s.store.OAuthClients.FindBy("client_id", clientID)) != nil {
			continue
		}
		keyID := seed.KeyID
		if keyID == "" {
			keyID = "TESTKEY001"
		}
		s.store.OAuthClients.Insert(corestore.Record{
			"client_id":     clientID,
			"team_id":       seed.TeamID,
			"key_id":        keyID,
			"name":          seed.Name,
			"redirect_uris": seed.RedirectURIs,
		})
	}
}
