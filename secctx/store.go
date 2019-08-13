package secctx

import "net/http"

// Store is an interface for storage of SSPI context handles.
// SSPI context handles are Windows API handles and have nothing to do
// with the "context" package in Go.
type Store interface {
	GetHandle(r *http.Request) (interface{}, error)
	SetHandle(r *http.Request, w http.ResponseWriter, contextHandle interface{}) error
}
