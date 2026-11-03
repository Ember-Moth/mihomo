package auth

import (
	A "github.com/metacubex/mihomo/component/auth"
	"sync"
	"testing"
)

func TestAuthenticationCanChangeDuringAccept(t *testing.T) {
	store := NewAuthStore(nil)
	user := A.NewAuthenticator([]A.AuthUser{{User: "u", Pass: "p"}})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			store.SetAuthenticator(user)
			store.SetAuthenticator(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			if a := store.Authenticator(); a != nil && !a.Verify("u", "p") {
				t.Error("invalid authentication snapshot")
			}
		}
	}()
	wg.Wait()
}
