package auth

import (
	"sync"
	"time"
)

type Credential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	AccountID       string
	PrincipalARN    string
	ExpiresAt       time.Time
	SessionTags     map[string]string
	TransitiveTags  []string
	Disabled        bool
}

type Store struct {
	mu          sync.RWMutex
	credentials map[string]Credential
}

type credentialResolution int

const (
	credentialMissing credentialResolution = iota
	credentialResolved
	credentialExpired
)

func NewStore(credentials ...Credential) *Store {
	store := &Store{credentials: map[string]Credential{}}
	for _, credential := range credentials {
		if credential.AccessKeyID == "" {
			continue
		}
		store.credentials[credential.AccessKeyID] = cloneCredential(credential)
	}
	return store
}

func (store *Store) Resolve(accessKeyID string) (Credential, bool) {
	credential, resolution := store.resolve(accessKeyID)
	return credential, resolution == credentialResolved
}

func (store *Store) resolve(accessKeyID string) (Credential, credentialResolution) {
	if store == nil || accessKeyID == "" {
		return Credential{}, credentialMissing
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	credential, ok := store.credentials[accessKeyID]
	if !ok || credential.Disabled {
		return Credential{}, credentialMissing
	}
	if !credential.ExpiresAt.IsZero() && time.Now().UTC().After(credential.ExpiresAt) {
		return Credential{}, credentialExpired
	}
	return cloneCredential(credential), credentialResolved
}

func (store *Store) Put(credential Credential) bool {
	if store == nil || credential.AccessKeyID == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.credentials[credential.AccessKeyID] = cloneCredential(credential)
	return true
}

func (store *Store) Delete(accessKeyID string) bool {
	if store == nil || accessKeyID == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.credentials[accessKeyID]; !ok {
		return false
	}
	delete(store.credentials, accessKeyID)
	return true
}

func cloneCredential(credential Credential) Credential {
	if credential.SessionTags != nil {
		tags := make(map[string]string, len(credential.SessionTags))
		for key, value := range credential.SessionTags {
			tags[key] = value
		}
		credential.SessionTags = tags
	}
	if credential.TransitiveTags != nil {
		credential.TransitiveTags = append([]string(nil), credential.TransitiveTags...)
	}
	return credential
}
