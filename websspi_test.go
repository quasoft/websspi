package websspi

import (
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

type stubAPI struct {
	acquireStatus    SECURITY_STATUS // if stub should return True in simulated calls to AcquireCredentialsHandle
	acceptStatus     SECURITY_STATUS // if stub should return True in simulated calls to AcceptSecurityContext
	deleteStatus     SECURITY_STATUS // if stub should return True in simulated calls to DeleteSecurityContext
	queryStatus      SECURITY_STATUS // if stub should return True in simulated calls to QueryContextAttributes
	freeBufferStatus SECURITY_STATUS // if stub should return True in simulated calls to FreeContextBuffer
	freeCredsStatus  SECURITY_STATUS // if stub should return True in simulated calls to FreeCredentialsHandle
	validToken       string          // value that will be asumed to be a valid token
}

func (s *stubAPI) AcquireCredentialsHandle(
	principal *uint16,
	_package *uint16,
	credentialUse uint32,
	logonId *LUID,
	authData *byte,
	getKeyFn uintptr,
	getKeyArgument uintptr,
	credHandle *CredHandle,
	expiry *syscall.Filetime,
) SECURITY_STATUS {
	if s.acquireStatus != SEC_E_OK {
		return s.acquireStatus
	}
	credHandle = &CredHandle{}
	expiry = &syscall.Filetime{}
	return SEC_E_OK
}

func (s *stubAPI) AcceptSecurityContext(
	credential *CredHandle,
	context *CtxtHandle,
	input *SecBufferDesc,
	contextReq uint32,
	targDataRep uint32,
	newContext *CtxtHandle,
	output *SecBufferDesc,
	contextAttr *uint32,
	expiry *syscall.Filetime,
) SECURITY_STATUS {
	return s.acceptStatus
}

func (s *stubAPI) QueryContextAttributes(context *CtxtHandle, attribute uint32, buffer *byte) SECURITY_STATUS {
	return s.queryStatus
}

func (s *stubAPI) DeleteSecurityContext(context *CtxtHandle) SECURITY_STATUS {
	return s.deleteStatus
}

func (s *stubAPI) FreeContextBuffer(buffer *byte) SECURITY_STATUS {
	return SEC_E_OK
}

func (s *stubAPI) FreeCredentialsHandle(handle *CredHandle) SECURITY_STATUS {
	return SEC_E_OK
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
func newTestAuthenticator(t *testing.T) *Authenticator {
	config := Config{
		contextStore: &stubContextStore{},
		authAPI:      &stubAPI{SEC_E_OK, SEC_E_OK, SEC_E_OK, SEC_E_OK, SEC_E_OK, SEC_E_OK, "a87421000492aa874209af8bc028"},
		KrbPrincipal: "service@test.local",
	}
	auth, err := New(&config)
	if err != nil {
		t.Errorf("could not create new authenticator: %s", err)
	}
	return auth
}

func TestConfigValidate_NoContextStore(t *testing.T) {
	config := NewConfig()
	config.contextStore = nil
	err := config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() returned nil (no error) when contextStore was nil, wanted error")
	}
}

func TestConfigValidate_NoAuthAPI(t *testing.T) {
	config := NewConfig()
	config.authAPI = nil
	err := config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() returned nil (no error) when authAPI was nil, wanted error")
	}
}

func TestConfigValidate_Complete(t *testing.T) {
	config := NewConfig()
	config.KrbPrincipal = "service@test.local"
	err := config.Validate()
	if err != nil {
		t.Errorf("Config.Validate() returned error for a valid config, wanted nil (no error)")
	}
}

func TestNewAuthenticator_InvalidConfig(t *testing.T) {
	_, err := New(&Config{})
	if err == nil {
		t.Errorf("New() returns nil (no error) when Config was not valid, wanted error")
	}
}

func TestNewAuthenticator_ErrorOnAcquire(t *testing.T) {
	config := Config{
		contextStore: &stubContextStore{},
		authAPI:      &stubAPI{acquireStatus: SEC_E_INSUFFICIENT_MEMORY},
		KrbPrincipal: "service@test.local",
	}
	_, err := New(&config)
	if err == nil {
		t.Errorf("New() returns nil (no error) when AcquireCredentialHandle fails, wanted error")
	}
}

func TestAuthenticate_NoAuthHeader(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)

	_, err := auth.Authenticate(r, nil)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request without Authorization header, wanted an error")
	}
}

func TestAuthenticate_MultipleAuthHeaders(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Add("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc028")
	r.Header.Add("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc029")

	_, err := auth.Authenticate(r, nil)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with multiple Authorization headers, wanted an error")
	}
}

func TestAuthenticate_EmptyAuthHeader(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "")

	_, err := auth.Authenticate(r, nil)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with empty Authorization header, wanted an error")
	}
}

func TestAuthenticate_BadAuthPrefix(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "auth: neg")

	_, err := auth.Authenticate(r, nil)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with bad Authorization header, wanted an error")
	}
}

func TestAuthenticate_EmptyToken(t *testing.T) {
	auth := newTestAuthenticator(t)

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

			_, err := auth.Authenticate(r, nil)
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
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a874-210004-92aa8742-09af8-bc028")

	_, err := auth.Authenticate(r, nil)
	if err == nil {
		t.Error("Authenticate() returned nil (no error) for request with token that is not valid base64 string, wanted an error")
	}
}

func TestAuthenticate_ValidBase64(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")

	_, err := auth.Authenticate(r, nil)
	if err != nil {
		t.Errorf(
			"Authenticate() returned error %q for request with valid base64 string, wanted nil (no error)",
			err,
		)
	}
}

func TestAuthenticate_ValidToken(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")

	_, err := auth.Authenticate(r, nil)
	if err != nil {
		t.Errorf(
			"Authenticate() with valid token returned error %q, wanted nil (no error)",
			err,
		)
	}
}

func TestWithAuth_ValidToken(t *testing.T) {
	auth := newTestAuthenticator(t)

	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")
	w := httptest.NewRecorder()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})
	protectedHandler := auth.WithAuth(handler)
	protectedHandler.ServeHTTP(w, r)

	_ = auth.Free()

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
