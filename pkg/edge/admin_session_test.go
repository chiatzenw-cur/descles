package edge

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsoleBrowserSessionAndRevocation(t *testing.T) {
	access, err := OpenAdminAccess(filepath.Join(t.TempDir(), "console-users.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := access.Issue("alice", "Alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenApprovals(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a := &ApprovalAdmin{Store: store, Token: "owner-secret", Access: access}
	mux := http.NewServeMux()
	a.Register(mux)
	call := func(method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:8081"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:12345"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := call("POST", "/admin/session", `{"token":"`+key+`","remember":true}`, nil, "http://localhost:8081")
	if w.Code != 200 {
		t.Fatalf("sign in: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != consoleSessionCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < 29*24*3600 || strings.Contains(cookie.Value, key) {
		t.Fatalf("unsafe session cookie: %+v", cookie)
	}
	short := call("POST", "/admin/session", `{"token":"`+key+`","remember":false}`, nil, "http://localhost:8081")
	if short.Code != 200 || len(short.Result().Cookies()) != 1 || short.Result().Cookies()[0].MaxAge != 0 {
		t.Fatalf("browser-only session: %d", short.Code)
	}
	if w := call("GET", "/admin/me", "", cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"alice"`) {
		t.Fatalf("cookie identity: %d %s", w.Code, w.Body.String())
	}
	if w := call("POST", "/admin/approvals/abc/approve", `{}`, cookie, "http://attacker.example"); w.Code != 403 {
		t.Fatalf("cross-origin write: %d", w.Code)
	}
	if w := call("POST", "/admin/approvals/abc/approve", `{}`, cookie, "http://localhost:8081"); w.Code == 403 || w.Code == 401 {
		t.Fatalf("same-origin write blocked: %d", w.Code)
	}
	if w := call("DELETE", "/admin/session", "", cookie, "http://localhost:8081"); w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("sign out: %d %s", w.Code, w.Body.String())
	}
	if err := access.Revoke("alice"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/admin/me", "", cookie, ""); w.Code != 401 {
		t.Fatalf("revoked session: %d", w.Code)
	}
	if _, err := access.Issue("alice", "Alice again", "admin"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/admin/me", "", cookie, ""); w.Code != 401 {
		t.Fatalf("old session revived by reissue: %d", w.Code)
	}
}

func TestConsoleSessionExpiryTamperingAndTransport(t *testing.T) {
	a := &ApprovalAdmin{Token: "owner-secret"}
	digest := tokenHash(a.Token)
	for _, raw := range []string{a.signedSession(digest, time.Now().Add(-time.Minute)), a.signedSession(digest, time.Now().Add(31*24*time.Hour)), a.signedSession(digest, time.Now().Add(time.Hour)) + "x"} {
		if _, ok := a.resolveSession(raw); ok {
			t.Fatal("invalid session accepted")
		}
	}
	store, err := OpenApprovals(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a.Store = store
	mux := http.NewServeMux()
	a.Register(mux)
	r := httptest.NewRequest("POST", "http://edge.example/admin/session", strings.NewReader(`{"token":"owner-secret","remember":true}`))
	r.RemoteAddr = "203.0.113.10:12000"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("remote HTTP sign-in: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://edge.example/admin/session", strings.NewReader(`{"token":"owner-secret","remember":true}`))
	r.RemoteAddr = "127.0.0.1:12000"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("non-local HTTP host through loopback proxy: %d", w.Code)
	}
}
