package edgeapp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCustomerWorkspaceServesDashboardAndScopesLocalUsage(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/me":
			switch r.Header.Get("Authorization") {
			case "Bearer platform":
				w.Write([]byte(`{"scope":"platform"}`))
			case "Bearer customer":
				w.Write([]byte(`{"scope":"org","org_id":"customer-org"}`))
			case "Bearer other":
				w.Write([]byte(`{"scope":"org","org_id":"other-org"}`))
			default:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
		case "/control/orgs":
			if r.Header.Get("Authorization") != "Bearer platform" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`[{"id":"customer-org"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	origin, _ := url.Parse(control.URL)
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/costs" || r.Header.Get("X-Descles-Org") != "" {
			http.Error(w, "unexpected local request", http.StatusBadRequest)
			return
		}
		w.Write([]byte(`[{"cost_usd":1}]`))
	})
	mux := http.NewServeMux()
	registerCustomerWorkspace(mux, local, origin, "customer-org")
	for _, tc := range []struct {
		path, token string
		want        int
		contains    string
	}{
		{"/", "", http.StatusOK, "/edge_features.js"},
		{"/app.js", "", http.StatusOK, "/control/me"},
		{"/edge_features.js", "", http.StatusOK, "Trace mining"},
		{"/control/orgs", "platform", http.StatusOK, "customer-org"},
		{"/api/costs", "", http.StatusUnauthorized, ""},
		{"/api/costs", "invalid", http.StatusUnauthorized, ""},
		{"/api/costs", "other", http.StatusForbidden, ""},
		{"/api/costs", "customer", http.StatusOK, "cost_usd"},
		{"/api/costs", "platform", http.StatusOK, "cost_usd"},
		{"/api/unknown", "platform", http.StatusNotFound, ""},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		r.Header.Set("X-Descles-Org", "other-org")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.contains) {
			t.Errorf("GET %s (%s): status=%d body=%q, want %d containing %q", tc.path, tc.token, w.Code, w.Body.String(), tc.want, tc.contains)
		}
		if tc.path == "/" && (w.Header().Get("Content-Security-Policy") == "" || !strings.Contains(w.Body.String(), `data-customer-edge="true"`)) {
			t.Error("customer workspace missing its deployment marker or content security policy")
		}
	}
	post := httptest.NewRecorder()
	mux.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/costs", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/costs: got %d, want 405", post.Code)
	}
}
