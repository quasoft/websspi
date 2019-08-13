package secctx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetHandle(t *testing.T) {
	store := NewCookieStore()
	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")
	w := httptest.NewRecorder()

	ctx := 314
	err := store.SetHandle(r, w, &ctx)
	if err != nil {
		t.Fatalf("SetHandle() failed with error %q, wanted no error", err)
	}
	gotCookie := w.Header().Get("Set-Cookie")
	wantCookie := "websspi="
	if !strings.HasPrefix(gotCookie, wantCookie) {
		t.Errorf("SetHandle() failed to set encrypted websspi cookie, got = %q, want %q", gotCookie, wantCookie)
	}
}

func TestGetHandle(t *testing.T) {
	store := NewCookieStore()
	r := httptest.NewRequest("GET", "http://example.local/", nil)
	r.Header.Set("Authorization", "Negotiate a87421000492aa874209af8bc028")
	w := httptest.NewRecorder()

	var wantCtxHandle uint32 = 314
	err := store.SetHandle(r, w, wantCtxHandle)
	if err != nil {
		t.Fatalf("SetHandle() failed with error %q, wanted no error", err)
	}

	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	handle, err := store.GetHandle(r)
	if err != nil {
		t.Fatalf("GetHandle() failed with error %q, wanted no error", err)
	}
	gotCtxHandle, ok := handle.(uint32)
	if !ok {
		t.Fatal("SetHandle() followed by GetHandle() returned value of different type")
	}
	if gotCtxHandle != wantCtxHandle {
		t.Errorf("GetHandle() returned wrong context handle, got = %v, want %v", gotCtxHandle, wantCtxHandle)
	}
}
