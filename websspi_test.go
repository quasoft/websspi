package websspi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubAPI struct {
	acceptOK bool // if stub should return True in simulated calls to Accept
}

func (s *stubAPI) AcceptSecurityContext(token string) error {
	if !s.acceptOK {
		return fmt.Errorf("simulated failure of AcceptSecurityContext")
	}
	return nil
}

// newTestAuthenticator creates an Authenticator for use in tests.
func newTestAuthenticator() *Authenticator {
	config := Config{
		KrbPrincipal: "service@test.local",
	}
	auth := Authenticator{
		Config:  config,
		authAPI: &stubAPI{},
	}
	return &auth
}

func TestConfigValidate_Complete(t *testing.T) {
	config := NewConfig()
	config.KrbPrincipal = "service@test.local"
	err := config.Validate()
	if err != nil {
		t.Errorf("Config.Validate() = false for a valid config, want true")
	}
}

func TestAuthenticate_ValidToken(t *testing.T) {
	auth := newTestAuthenticator()
	auth.authAPI.(*stubAPI).acceptOK = true

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("WWW-Authenticate", "TODO: Put a valid test token here for site example.local")

	_, err := auth.Authenticate(r)
	if err != nil {
		t.Errorf(
			"Authenticate() with valid token returned error %q, wanted nil (no error)",
			err,
		)
	}
}

func TestWithAuth_ValidToken(t *testing.T) {
	auth := newTestAuthenticator()
	auth.authAPI.(*stubAPI).acceptOK = true

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("WWW-Authenticate", "TODO: Put a valid test token here for site example.local")
	w := httptest.NewRecorder()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})
	protectedHandler := auth.WithAuth(handler)
	protectedHandler.ServeHTTP(w, r)

	code := w.Result().StatusCode
	if code != http.StatusOK {
		t.Errorf(
			"Got status %v for request with valid token, wanted StatusOK (%v)",
			code,
			http.StatusOK,
		)
	}

	if code != http.StatusOK && handlerCalled {
		t.Error("Handler was called, when status code was not OK. Handler should not be called for error status codes.")
	} else if code == http.StatusOK && !handlerCalled {
		t.Error("Handler was not called, even though token was valid")
	}
}
