package clerk

import corestore "github.com/vercel-labs/emulate/internal/core/store"

type Store struct {
	Users          *corestore.Collection
	EmailAddresses *corestore.Collection
	Organizations  *corestore.Collection
	Memberships    *corestore.Collection
	Invitations    *corestore.Collection
	Sessions       *corestore.Collection
	OAuthApps      *corestore.Collection
	OAuthCodes     *corestore.Collection
	AccessTokens   *corestore.Collection
}

func NewStore(store *corestore.Store) Store {
	return Store{
		Users:          store.MustCollection("clerk.users", "clerk_id", "username"),
		EmailAddresses: store.MustCollection("clerk.emails", "email_id", "user_id", "email_address"),
		Organizations:  store.MustCollection("clerk.orgs", "clerk_id", "slug"),
		Memberships:    store.MustCollection("clerk.memberships", "membership_id", "org_id", "user_id"),
		Invitations:    store.MustCollection("clerk.invitations", "invitation_id", "org_id"),
		Sessions:       store.MustCollection("clerk.sessions", "clerk_id", "user_id"),
		OAuthApps:      store.MustCollection("clerk.oauth_apps", "app_id", "client_id"),
		OAuthCodes:     store.MustCollection("clerk.oauth_codes", "code", "client_id", "user_id"),
		AccessTokens:   store.MustCollection("clerk.access_tokens", "token", "user_id", "session_id"),
	}
}
