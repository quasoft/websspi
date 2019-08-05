package websspi

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/quasoft/websspi/sspicontext"
)

type authAPI interface {
	AcquireCredentialsHandle(principal string) (*CredHandle, *time.Time, error)
	AcceptSecurityContext(credential *CredHandle, context *CtxtHandle, input []byte) (newCtx *CtxtHandle, out []byte, exp *time.Time, status SECURITY_STATUS, err error)
	FreeCredentialsHandle(handle *CredHandle) error
}

// The Config object determines the behaviour of the Authenticator.
type Config struct {
	contextStore sspicontext.Store
	authAPI      authAPI
	KrbPrincipal string // Name of Kerberos principle used by the service
}

// NewConfig creates a configuration object with default values.
func NewConfig() *Config {
	return &Config{
		contextStore: sspicontext.NewCookieStore(),
		authAPI:      &sspiAPI{},
	}
}

// Validate makes basic validation of configuration to make sure that important and required fields
// have been set with values in expected format.
func (c *Config) Validate() error {
	if c.contextStore == nil {
		return errors.New("Store for context handles not specified in Config")
	}
	if c.authAPI == nil {
		return errors.New("Authentication API not specified in Config")
	}
	return nil
}

// The Authenticator type provides middleware methods for authentication of http requests.
// A single authenticator object can be shared by concurrent goroutines.
type Authenticator struct {
	Config     Config
	serverCred *CredHandle
	credExpiry *time.Time
}

// New creates a new Authenticator object with the given configuration options.
func New(config *Config) (*Authenticator, error) {
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	credential, expiry, err := config.authAPI.AcquireCredentialsHandle(config.KrbPrincipal)
	if err != nil {
		return nil, fmt.Errorf("could not acquire service credentials handle: %v", err)
	}
	log.Printf("Credential handle expiry: %v\n", *expiry)

	var auth = &Authenticator{
		Config:     *config,
		serverCred: credential,
		credExpiry: expiry,
	}

	return auth, nil
}

// Free method should be called before shutting down the server to let
// it release allocated Win32 resources
func (a *Authenticator) Free() error {
	if a.serverCred != nil {
		err := a.Config.authAPI.FreeCredentialsHandle(a.serverCred)
		if err != nil {
			return err
		}
	}
	return nil
}

// Authenticate tries to authenticate the HTTP request and returns nil
// if authentication was successful.
// Returns error and data for continuation if authentication was not successful.
func (a *Authenticator) Authenticate(r *http.Request, w http.ResponseWriter) (string, error) {
	// TODO:
	// 1. Check if Authorization header is present
	headers := r.Header["Authorization"]
	if len(headers) == 0 {
		return "", errors.New("the Authorization header is not provided")
	}
	if len(headers) > 1 {
		return "", errors.New("received multiple Authorization headers, but expected only one")
	}

	authzHeader := strings.TrimSpace(headers[0])
	if authzHeader == "" {
		return "", errors.New("the Authorization header is empty")
	}
	// 1.1. Make sure header starts with "Negotiate"
	if !strings.HasPrefix(strings.ToLower(authzHeader), "negotiate") {
		return "", errors.New("the Authorization header does not start with 'Negotiate'")
	}

	// 2. Extract token from Authorization header
	authzParts := strings.Split(authzHeader, " ")
	if len(authzParts) < 2 {
		return "", errors.New("the Authorization header does not contain token (gssapi-data)")
	}
	token := authzParts[len(authzParts)-1]
	if token == "" {
		return "", errors.New("the token (gssapi-data) in the Authorization header is empty")
	}

	// 3. Decode token
	input, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", errors.New("could not decode token as base64 string")
	}

	// 4. Authenticate user with provided token
	sessionHandle, err := a.Config.contextStore.GetHandle(r)
	if err != nil {
		return "", fmt.Errorf("could not get context handle from store: %s", err)
	}
	var contextHandle *CtxtHandle
	if contextHandle, ok := sessionHandle.(*CtxtHandle); ok {
		log.Printf("CtxHandle: 0x%x\n", *contextHandle)
	} else {
		log.Printf("CtxHandle: nil\n")
	}
	newCtx, output, _, status, err := a.Config.authAPI.AcceptSecurityContext(
		a.serverCred,
		contextHandle,
		input,
	)
	log.Printf("Accept status: 0x%x\n", status)
	if newCtx != nil {
		a.Config.contextStore.SetHandle(r, w, newCtx)
		log.Printf("New context: 0x%x\n", *newCtx)
	} else {
		log.Printf("New context: nil\n")
	}
	if err != nil {
		return "", fmt.Errorf("AcceptSecurityContext failed with status 0x%x; error: %s", status, err)
	}
	if status == SEC_I_CONTINUE_NEEDED {
		// Negotiation should continue by sending the output data back to the client
		return base64.StdEncoding.EncodeToString(output), errors.New("Negotiation should continue")
	}

	// 5. Get username
	// 6. Store username in context
	return "", nil
}

// Return401 populates WWW-Authenticate header, indicating to client that authentication
// is required and returns a 401 (Unauthorized) response code.
// The data parameter can be empty for the first 401 response from the server.
// For subsequent 401 responses the data parameter should contain the gssapi-data,
// which is required for continuation of the negotiation.
func (a *Authenticator) Return401(w http.ResponseWriter, data string) {
	value := "Negotiate"
	if data != "" {
		value += " " + data
	}
	w.Header().Set("WWW-Authenticate", value)
	http.Error(w, "Error!", http.StatusUnauthorized)
}

// WithAuth authenticates the request. On successful authentication the request
// is passed down to the next http handler. The next handler can access information
// about the authenticated user via the GetUserName method.
// If authentication was not successful, the server returns 401 response code with
// a WWW-Authenticate, indicating that authentication is required.
func (a *Authenticator) WithAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Authenticating request to %s\n", r.RequestURI)

		data, err := a.Authenticate(r, w)
		if err != nil {
			log.Printf("Authentication failed with error: %v\n", err)
			a.Return401(w, data)
			return
		}

		log.Print("Authenticated\n")
		next.ServeHTTP(w, r)
	})
}

func init() {
	gob.Register(&CtxtHandle{})
}
