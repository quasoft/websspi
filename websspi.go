package websspi

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// The Config object determines the behaviour of the Authenticator.
type Config struct {
	KrbPrincipal string // Name of Kerberos principle used by the service
}

// NewConfig creates a configuration object with default values.
func NewConfig() *Config {
	return &Config{}
}

// Validate makes basic validation of configuration to make sure that important and required fields
// have been set with values in expected format.
func (c Config) Validate() error {
	return errors.New("not implemented")
}

type authAPI interface {
	AcceptSecurityContext(token string) error
}

// The Authenticator type provides middleware methods for authentication of http requests.
// A single authenticator object can be shared by concurrent goroutines.
type Authenticator struct {
	Config  Config
	authAPI authAPI
}

// New creates a new Authenticator object with the given configuration options.
func New(config *Config) (*Authenticator, error) {
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	var auth = &Authenticator{
		Config:  *config,
		authAPI: &sspiAPI{},
	}
	return auth, nil
}

// Authenticate tries to authenticate the HTTP request and returns nil
// if authentication was successful.
// Returns error and data for continuation if authentication was not successful.
func (a *Authenticator) Authenticate(r *http.Request) (string, error) {
	// TODO:
	// 1. Check if Authorization header is present
	authzHeader := r.Header.Get("Authorization")
	if authzHeader == "" {
		return "", errors.New("the Authorization header was not provided")
	}
	// 1.1. Make sure header starts with "Negotiate"
	if !strings.HasPrefix(strings.ToLower(authzHeader), "negotiate") {
		return "", errors.New("the Authorization header does not start with 'Negotiate'")
	}

	// 2. Extract token from authenticate header
	// 3. Parse token
	// 4. Authenticate user with provided token
	// 5. Get username
	// 6. Store username in context
	return "", errors.New("not implemented")
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
	log.Print("WithAuth called")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Authenticating request to %s", r.RequestURI)

		data, err := a.Authenticate(r)
		if err != nil {
			a.Return401(w, data)
			return
		}

		log.Print("Authenticated")
		next.ServeHTTP(w, r)
	})
}
