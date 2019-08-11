package websspi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

type stubAPI struct {
	acquireStatus    SECURITY_STATUS // the status code that should be returned in simulated calls to AcquireCredentialsHandle
	acceptStatus     SECURITY_STATUS // the status code that should be returned in simulated calls to AcceptSecurityContext
	acceptNewCtx     *CtxtHandle     // the context handle to be returned in simulated calls to AcceptSecurityContext
	acceptOutBuf     *SecBuffer      // the output buffer to be returned in simulated calls to AcceptSecurityContext
	deleteStatus     SECURITY_STATUS // the status code that should be returned in simulated calls to DeleteSecurityContext
	deleteCalled     bool            // true if DeleteSecurityContext has been called
	queryStatus      SECURITY_STATUS // the status code that should be returned in simulated calls to QueryContextAttributes
	freeBufferStatus SECURITY_STATUS // the status code that should be returned in simulated calls to FreeContextBuffer
	freeCredsStatus  SECURITY_STATUS // the status code that should be returned in simulated calls to FreeCredentialsHandle
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
	if s.acceptNewCtx != nil {
		*newContext = *s.acceptNewCtx
	}
	if s.acceptOutBuf != nil {
		*output.Buffers = *s.acceptOutBuf
	}
	return s.acceptStatus
}

func (s *stubAPI) QueryContextAttributes(context *CtxtHandle, attribute uint32, buffer *byte) SECURITY_STATUS {
	return s.queryStatus
}

func (s *stubAPI) DeleteSecurityContext(context *CtxtHandle) SECURITY_STATUS {
	s.deleteCalled = true
	return s.deleteStatus
}

func (s *stubAPI) FreeContextBuffer(buffer *byte) SECURITY_STATUS {
	return s.freeBufferStatus
}

func (s *stubAPI) FreeCredentialsHandle(handle *CredHandle) SECURITY_STATUS {
	return s.freeCredsStatus
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
		authAPI: &stubAPI{
			acquireStatus:    SEC_E_OK,
			acceptStatus:     SEC_E_OK,
			acceptNewCtx:     nil,
			acceptOutBuf:     nil,
			deleteStatus:     SEC_E_OK,
			queryStatus:      SEC_E_OK,
			freeBufferStatus: SEC_E_OK,
			freeCredsStatus:  SEC_E_OK,
			validToken:       "a87421000492aa874209af8bc028",
		},
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

func TestFree_ErrorOnFreeCredentials(t *testing.T) {
	config := Config{
		contextStore: &stubContextStore{},
		authAPI:      &stubAPI{freeCredsStatus: SEC_E_INVALID_HANDLE},
		KrbPrincipal: "service@test.local",
	}
	auth, err := New(&config)
	if err != nil {
		t.Fatalf("New() failed with valid config, error: %v", err)
	}
	err = auth.Free()
	if err == nil {
		t.Error("Free() returns nil (no error) when FreeCredentialsHandle fails, wanted error")
	}
}

func TestFree_DeleteContexts(t *testing.T) {
	auth := newTestAuthenticator(t)
	r := httptest.NewRequest("GET", "http://localhost:9000/", nil)
	w := httptest.NewRecorder()
	ctx := CtxtHandle{42, 314}
	err := auth.SetCtxHandle(r, w, &ctx)
	if err != nil {
		t.Fatalf("SetCtxHandle() failed with error %s, wanted no error", err)
	}
	err = auth.Free()
	if err != nil {
		t.Fatalf("Free() failed with error %s, wanted no error", err)
	}
	if !auth.Config.authAPI.(*stubAPI).deleteCalled {
		t.Errorf("Free() did NOT call DeleteSecurityContext, wanted at least one call")
	}
	if len(auth.ctxList) > 0 {
		t.Errorf("Free() did not delete all contexts. Have %d contexts, wanted 0", len(auth.ctxList))
	}
}

func TestFree_ErrorOnDeleteContexts(t *testing.T) {
	auth := newTestAuthenticator(t)
	auth.Config.authAPI.(*stubAPI).deleteStatus = SEC_E_INTERNAL_ERROR
	r := httptest.NewRequest("GET", "http://localhost:9000/", nil)
	w := httptest.NewRecorder()
	ctx := CtxtHandle{42, 314}
	err := auth.SetCtxHandle(r, w, &ctx)
	if err != nil {
		t.Fatalf("SetCtxHandle() failed with error %s, wanted no error", err)
	}
	err = auth.Free()
	if err == nil {
		t.Errorf("Free() returns no error when DeleteSecurityContext fails, wanted an error")
	}
}

func TestAcceptOrContinue_WithEmptyInput(t *testing.T) {
	auth := newTestAuthenticator(t)
	_, _, _, _, err := auth.AcceptOrContinue(nil, nil)
	// AcceptOrContinue should not panic on nil arguments
	if err == nil {
		t.Error("AcceptOrContinue(nil, nil) returned no error, should have returned an error")
	}
}

func TestAcceptOrContinue_WithOutputBuffer(t *testing.T) {
	wantData := [5]byte{2, 4, 8, 16, 32}
	buf := SecBuffer{uint32(len(wantData)), SECBUFFER_TOKEN, &wantData[0]}
	auth := newTestAuthenticator(t)
	auth.Config.authAPI.(*stubAPI).acceptOutBuf = &buf
	_, gotOut, _, _, _ := auth.AcceptOrContinue(nil, []byte{0})
	if gotOut == nil {
		t.Fatalf("AcceptOrContinue() returned no output data, wanted %v", wantData)
	}
	if !bytes.Equal(gotOut, wantData[:]) {
		t.Errorf("AcceptOrContinue() got %v for output data, wanted %v", gotOut, wantData)
	}
}

func TestAcceptOrContinue_ErrorOnFreeBuffer(t *testing.T) {
	data := [1]byte{0}
	buf := SecBuffer{uint32(len(data)), SECBUFFER_TOKEN, &data[0]}
	auth := newTestAuthenticator(t)
	auth.Config.authAPI.(*stubAPI).acceptOutBuf = &buf
	auth.Config.authAPI.(*stubAPI).freeBufferStatus = SEC_E_INVALID_HANDLE
	_, _, _, _, err := auth.AcceptOrContinue(nil, []byte{0})
	if err == nil {
		t.Error("AcceptOrContinue() returns no error when FreeContextBuffer fails, should have returned an error")
	}
}

func TestAcceptOrContinue_WithoutNewContext(t *testing.T) {
	auth := newTestAuthenticator(t)
	auth.Config.authAPI.(*stubAPI).acceptNewCtx = &CtxtHandle{0, 0}
	newCtx, _, _, _, _ := auth.AcceptOrContinue(nil, []byte{0})
	if newCtx != nil {
		t.Error("AcceptOrContinue() returned a new context handle for a simulated call to AcceptSecurityContext that returns NULL")
	}
}

func TestAcceptOrContinue_WithNewContext(t *testing.T) {
	auth := newTestAuthenticator(t)
	auth.Config.authAPI.(*stubAPI).acceptNewCtx = &CtxtHandle{42, 314}
	gotNewCtx, _, _, _, _ := auth.AcceptOrContinue(nil, []byte{0})
	if gotNewCtx == nil {
		t.Fatal("AcceptOrContinue() returned nil for new context handle for a simulated call to AcceptSecurityContext that returns a valid handle")
	}
	wantNewCtx := &CtxtHandle{42, 314}
	if *gotNewCtx != *wantNewCtx {
		t.Errorf("AcceptOrContinue() got new context handle = %v, want %v (returned by AcceptSecurityContext)", *gotNewCtx, *wantNewCtx)
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
