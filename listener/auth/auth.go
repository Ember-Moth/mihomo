package auth

import (
	"github.com/metacubex/mihomo/component/auth"
	"sync"
)

type authStore struct {
	mu            sync.RWMutex
	authenticator auth.Authenticator
}

func (a *authStore) Authenticator() auth.Authenticator {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authenticator
}

func (a *authStore) SetAuthenticator(authenticator auth.Authenticator) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authenticator = authenticator
}

func NewAuthStore(authenticator auth.Authenticator) auth.AuthStore {
	return &authStore{authenticator: authenticator}
}

var Default auth.AuthStore = NewAuthStore(nil)

type nilAuthStore struct{}

func (a *nilAuthStore) Authenticator() auth.Authenticator {
	return nil
}

func (a *nilAuthStore) SetAuthenticator(authenticator auth.Authenticator) {}

var Nil auth.AuthStore = (*nilAuthStore)(nil) // always return nil, even call SetAuthenticator() with a non-nil authenticator
