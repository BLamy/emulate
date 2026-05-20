package apple

import corestore "github.com/vercel-labs/emulate/internal/core/store"

type Store struct {
	Users         *corestore.Collection
	OAuthClients  *corestore.Collection
	OAuthCodes    *corestore.Collection
	RefreshTokens *corestore.Collection
	FirstAuth     *corestore.Collection
}

func NewStore(runtimeStore *corestore.Store) Store {
	return Store{
		Users:         runtimeStore.MustCollection("apple.users", "uid", "email"),
		OAuthClients:  runtimeStore.MustCollection("apple.oauth_clients", "client_id"),
		OAuthCodes:    runtimeStore.MustCollection("apple.oauth_codes", "code", "client_id", "email"),
		RefreshTokens: runtimeStore.MustCollection("apple.refresh_tokens", "token", "client_id", "email"),
		FirstAuth:     runtimeStore.MustCollection("apple.first_auth", "pair_key"),
	}
}
