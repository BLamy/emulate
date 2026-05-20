package google

import corestore "github.com/vercel-labs/emulate/internal/core/store"

type Store struct {
	Users           *corestore.Collection
	OAuthClients    *corestore.Collection
	OAuthCodes      *corestore.Collection
	AccessTokens    *corestore.Collection
	RefreshTokens   *corestore.Collection
	Labels          *corestore.Collection
	Messages        *corestore.Collection
	Attachments     *corestore.Collection
	Drafts          *corestore.Collection
	History         *corestore.Collection
	Filters         *corestore.Collection
	Forwarding      *corestore.Collection
	SendAs          *corestore.Collection
	Calendars       *corestore.Collection
	CalendarEvents  *corestore.Collection
	DriveItems      *corestore.Collection
	WatchRegistries *corestore.Collection
}

func NewStore(store *corestore.Store) Store {
	return Store{
		Users:           store.MustCollection("google.users", "uid", "email"),
		OAuthClients:    store.MustCollection("google.oauth_clients", "client_id"),
		OAuthCodes:      store.MustCollection("google.oauth_codes", "code"),
		AccessTokens:    store.MustCollection("google.oauth_access_tokens", "token"),
		RefreshTokens:   store.MustCollection("google.oauth_refresh_tokens", "token"),
		Labels:          store.MustCollection("google.labels", "gmail_id", "user_email", "name"),
		Messages:        store.MustCollection("google.messages", "gmail_id", "thread_id", "user_email"),
		Attachments:     store.MustCollection("google.attachments", "gmail_id", "message_gmail_id", "user_email"),
		Drafts:          store.MustCollection("google.drafts", "gmail_id", "message_gmail_id", "user_email"),
		History:         store.MustCollection("google.history", "gmail_id", "message_gmail_id", "user_email"),
		Filters:         store.MustCollection("google.filters", "gmail_id", "user_email"),
		Forwarding:      store.MustCollection("google.forwarding_addresses", "user_email", "forwarding_email"),
		SendAs:          store.MustCollection("google.send_as", "user_email", "send_as_email"),
		Calendars:       store.MustCollection("google.calendars", "google_id", "user_email"),
		CalendarEvents:  store.MustCollection("google.calendar_events", "google_id", "calendar_google_id", "user_email"),
		DriveItems:      store.MustCollection("google.drive_items", "google_id", "user_email", "mime_type"),
		WatchRegistries: store.MustCollection("google.watch_registries", "user_email"),
	}
}
