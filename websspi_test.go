package websspi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubAPI struct {
	acquireOK  bool   // if stub should return True in simulated calls to Acquire
	acceptOK   bool   // if stub should return True in simulated calls to Accept
	validToken string // value that will be asumed to be a valid token
}

func (s *stubAPI) AcquireCredentialsHandle(principal string) (*CredHandle, *time.Time, error) {
	if !s.acquireOK {
		return nil, nil, fmt.Errorf("simulated failure of AcquireCredentialsHandle")
	}
	return &CredHandle{}, &time.Time{}, nil
}

func (s *stubAPI) AcceptSecurityContext(token string) error {
	if !s.acceptOK {
		return fmt.Errorf("simulated failure of AcceptSecurityContext")
	}
	return nil
}

func (s *stubAPI) FreeCredentialsHandle(handle *CredHandle) error {
	return nil
}

type stubContextStore struct {
	contextHandle interface{}
}

func (s *stubContextStore) GetHandle(r *http.Request) (interface{}, error) {
	return s.contextHandle, nil
}

func (s *stubContextStore) SetHandle(r *http.Request, w http.ResponseWriter, contextHandle interface{}) error {
	s.contextHandle = contextHandle
	return nil
}

// newTestAuthenticator creates an Authenticator for use in tests.
func newTestAuthenticator() *Authenticator {
	config := Config{
		contextStore: &stubContextStore{},
		authAPI:      &stubAPI{true, true, "a87421000492aa874209af8bc028"},
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

func TestAuthenticate_NoAuthHeader(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)

	_, err := auth.Authenticate(r)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request without Authorization header, wanted an error")
	}
}

func TestAuthenticate_MultipleAuthHeaders(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Add("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc028")
	r.Header.Add("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc029")

	_, err := auth.Authenticate(r)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with multiple Authorization headers, wanted an error")
	}
}

func TestAuthenticate_EmptyAuthHeader(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "")

	_, err := auth.Authenticate(r)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with empty Authorization header, wanted an error")
	}
}

func TestAuthenticate_BadAuthPrefix(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "auth: neg")

	_, err := auth.Authenticate(r)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with bad Authorization header, wanted an error")
	}
}

func TestAuthenticate_EmptyToken(t *testing.T) {
	auth := newTestAuthenticator()

	tests := []struct {
		name  string
		value string
	}{
		{"No space delimiter and no token", "Negotiate"},
		{"Space delimiter, but no token", "Negotiate "},
		{"Double space delimiter, but no token", "Negotiate  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.local/", nil)
			r.Header.Set("Authorization", tt.value)

			_, err := auth.Authenticate(r)
			if err == nil {
				t.Errorf(
					"Authenticate() returned nil (no error) for request with bad Authorization header (%v), wanted an error",
					tt.name,
				)
			}
		})
	}
}

func TestAuthenticate_BadBase64(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc028")

	_, err := auth.Authenticate(r)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with token that is not valid base64 string, wanted an error")
	}
}

func TestAuthenticate_ValidBase64(t *testing.T) {
	auth := newTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")

	_, err := auth.Authenticate(r)
	if err != nil {
		t.Errorf(
			"Authenticate() returned error %q for request with valid base64 string, wanted nil (no error)",
			err,
		)
	}
}

func TestAuthenticate_ValidToken(t *testing.T) {
	auth := newTestAuthenticator()
	auth.authAPI.(*stubAPI).acceptOK = true
	auth.authAPI.(*stubAPI).validToken = "a87421000492aa874209af8bc028"

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")

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
	auth.authAPI.(*stubAPI).validToken = "a87421000492aa874209af8bc028"

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")
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
