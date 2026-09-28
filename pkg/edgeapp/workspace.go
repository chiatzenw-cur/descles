package edgeapp

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/web"
)

// registerCustomerWorkspace serves the former gateway dashboard from the edge
// in customer-hosted mode. Management stays at the customer's control plane;
// the dashboard's usage API reads this edge's own records. No vendor server is
// contacted. The caller passes only the origin of the already-validated bundle
// endpoint, never an origin supplied by a browser request.
func registerCustomerWorkspace(mux *http.ServeMux, localAPI http.Handler, controlOrigin *url.URL, orgID string) {
	assets := web.Handler()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(web.FS(), "index.html")
		if err != nil {
			http.Error(w, "workspace unavailable", http.StatusInternalServerError)
			return
		}
		html := strings.Replace(string(page), `<html lang="en">`, `<html lang="en" data-customer-edge="true">`, 1)
		html = strings.Replace(html, `<script src="/app.js"></script>`, `<script src="/app.js"></script><script src="/edge_features.js"></script>`, 1)
		html = strings.Replace(html, "Connect with your console administrator token.", "Connect with your customer control-plane administrator or organization token.", 1)
		html = strings.Replace(html, ">Administrator token</label>", ">Control-plane token</label>", 1)
		html = strings.Replace(html, "Use the token configured by your gateway administrator.", "Local edge approvals use a separate token at /admin/.", 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = io.WriteString(w, html)
	})
	serveAsset := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		assets.ServeHTTP(w, r)
	})
	for _, path := range []string{"/app.js", "/edge_features.js", "/style.css", "/brand.css", "/icons.js", "/icon.svg", "/brand-mark.svg"} {
		mux.Handle("GET "+path, serveAsset)
	}

	upstream := httputil.NewSingleHostReverseProxy(controlOrigin)
	originalDirector := upstream.Director
	upstream.Director = func(r *http.Request) {
		originalDirector(r)
		r.Host = controlOrigin.Host
		r.Header.Del("Cookie") // self-hosted control uses bearer tokens, not browser cookies
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 15 * time.Second
	upstream.Transport = transport
	upstream.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		workspaceError(w, http.StatusBadGateway, "customer control plane unavailable")
	}
	for _, prefix := range []string{"/control/", "/skills/", "/trust/"} {
		mux.Handle(prefix, upstream)
	}

	// The dashboard sends its control-plane bearer token to /api too. Verify it
	// with the customer control plane before reading local edge data. A token
	// for a different organization must never reveal this edge's records.
	verifyClient := provider.NoRedirectClient(5 * time.Second)
	mux.Handle("GET /api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !workspaceAPIPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || len(strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))) == 0 {
			workspaceError(w, http.StatusUnauthorized, "customer control-plane token required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		check, err := http.NewRequestWithContext(ctx, http.MethodGet, controlOrigin.String()+"/control/me", nil)
		if err != nil {
			workspaceError(w, http.StatusServiceUnavailable, "control-plane authentication unavailable")
			return
		}
		check.Header.Set("Authorization", auth)
		response, err := verifyClient.Do(check)
		if err != nil {
			workspaceError(w, http.StatusServiceUnavailable, "control-plane authentication unavailable")
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			workspaceError(w, http.StatusUnauthorized, "customer control-plane token required")
			return
		}
		var identity struct {
			Scope string `json:"scope"`
			OrgID string `json:"org_id"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&identity); err != nil ||
			(identity.Scope != "platform" && (identity.Scope != "org" || identity.OrgID != orgID)) {
			workspaceError(w, http.StatusForbidden, "token has no access to this edge")
			return
		}
		// The edge runs a single organization's data plane. The proxy's own
		// query handler uses its bundle key resolver, so the control-plane token
		// cannot be interpreted as an agent key or widen the data scope.
		r.Header.Del("X-Descles-Org")
		r.Header.Del("X-Descles-User")
		localAPI.ServeHTTP(w, r)
	}))
}

func workspaceError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func workspaceAPIPath(path string) bool {
	switch path {
	case "/api/spans", "/api/requests", "/api/costs", "/api/policy-events":
		return true
	}
	return strings.HasPrefix(path, "/api/traces/")
}
