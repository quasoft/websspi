package websspi

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/quasoft/websspi/sspicontext"
)

// The Config object determines the behaviour of the Authenticator.
type Config struct {
	contextStore sspicontext.Store
	authAPI      API
	KrbPrincipal string // Name of Kerberos principle used by the service
}

// NewConfig creates a configuration object with default values.
func NewConfig() *Config {
	return &Config{
		contextStore: sspicontext.NewCookieStore(),
		authAPI:      &Secur32{},
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

	var auth = &Authenticator{
		Config: *config,
	}

	err = auth.PrepareCredentials(config.KrbPrincipal)
	if err != nil {
		return nil, fmt.Errorf("could not acquire credentials handle for the service: %v", err)
	}
	log.Printf("Credential handle expiry: %v\n", *auth.credExpiry)

	return auth, nil
}

// PrepareCredentials method acquires a credentials handle for the specified principal
// for use during the live of the application.
// On success stores the handle in the serverCred field and its expiry time in the
// credExpiry field.
// This method must be called once - when the application is starting or when the first
// request from a client is received.
func (a *Authenticator) PrepareCredentials(principal string) error {
	var principalPtr *uint16
	if principal != "" {
		var err error
		principalPtr, err = syscall.UTF16PtrFromString(principal)
		if err != nil {
			return err
		}
	}
	credentialUsePtr, err := syscall.UTF16PtrFromString(NEGOSSP_NAME)
	if err != nil {
		return err
	}
	var handle CredHandle
	var expiry syscall.Filetime
	status := a.Config.authAPI.AcquireCredentialsHandle(
		principalPtr,
		credentialUsePtr,
		SECPKG_CRED_INBOUND,
		nil, // logonId
		nil, // authData
		0,   // getKeyFn
		0,   // getKeyArgument
		&handle,
		&expiry,
	)
	if status != SEC_E_OK {
		return fmt.Errorf("call to AcquireCredentialsHandle failed with code 0x%x", status)
	}
	expiryTime := time.Unix(0, expiry.Nanoseconds())
	a.credExpiry = &expiryTime
	a.serverCred = &handle
	return nil
}

// Free method should be called before shutting down the server to let
// it release allocated Win32 resources
func (a *Authenticator) Free() error {
	if a.serverCred != nil {
		status := a.Config.authAPI.FreeCredentialsHandle(a.serverCred)
		if status != SEC_E_OK {
			return fmt.Errorf("call to FreeCredentialsHandle failed with code 0x%x", status)
		}
		a.serverCred = nil
	}
	return nil
}

// AcceptOrContinue tries to validate the input token by calling the AcceptSecurityContext
// function and returns and error if validation failed or continuation of the negotiation is needed.
// No error is returned if the token was validated (user was authenticated).
func (a *Authenticator) AcceptOrContinue(context *CtxtHandle, input []byte) (newCtx *CtxtHandle, out []byte, exp *time.Time, status SECURITY_STATUS, err error) {
	var inputDesc SecBufferDesc
	var inputBuf SecBuffer
	inputDesc.BuffersCount = 1
	inputDesc.Version = SECBUFFER_VERSION
	inputDesc.Buffers = &inputBuf
	inputBuf.BufferSize = uint32(len(input))
	inputBuf.BufferType = SECBUFFER_TOKEN
	inputBuf.Buffer = &input[0]

	var outputDesc SecBufferDesc
	var outputBuf SecBuffer
	outputDesc.BuffersCount = 1
	outputDesc.Version = SECBUFFER_VERSION
	outputDesc.Buffers = &outputBuf
	outputBuf.BufferSize = 0
	outputBuf.BufferType = SECBUFFER_TOKEN
	outputBuf.Buffer = nil

	var expiry syscall.Filetime
	var contextAttr uint32
	var newContextHandle CtxtHandle

	status = a.Config.authAPI.AcceptSecurityContext(
		a.serverCred,
		context,
		&inputDesc,
		ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_MUTUAL_AUTH, // contextReq uint32,
		SECURITY_NATIVE_DREP,                        // targDataRep uint32,
		&newContextHandle,
		&outputDesc,  // *SecBufferDesc
		&contextAttr, // contextAttr *uint32,
		&expiry,      // *syscall.Filetime
	)
	if newContextHandle.Lower != 0 || newContextHandle.Upper != 0 {
		newCtx = &newContextHandle
	}
	tm := time.Unix(0, expiry.Nanoseconds())
	exp = &tm
	if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		// Copy outputBuf.Buffer to out and free the outputBuf.Buffer
		out = make([]byte, outputBuf.BufferSize)
		var bufPtr = uintptr(unsafe.Pointer(outputBuf.Buffer))
		for i := 0; i < len(out); i++ {
			out[i] = *(*byte)(unsafe.Pointer(bufPtr))
			bufPtr++
		}
	}
	if outputBuf.Buffer != nil {
		freeStatus := a.Config.authAPI.FreeContextBuffer(outputBuf.Buffer)
		if freeStatus != SEC_E_OK {
			status = freeStatus
			err = fmt.Errorf("could not free output buffer; FreeContextBuffer() failed with code: 0x%x", freeStatus)
			return
		}
	}
	if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		// TODO: Call CompleteToken?
		if err != nil {
			return
		}
	}
	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED &&
		status != SEC_I_COMPLETE_NEEDED && status != SEC_I_COMPLETE_AND_CONTINUE {
		err = fmt.Errorf("call to AcceptSecurityContext failed with code 0x%x", status)
		return
	}
	// TODO: Return contextAttr?
	return
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
	newCtx, output, _, status, err := a.AcceptOrContinue(contextHandle, input)
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
