// Package web serves the Descles dashboard — a dependency-free single-page app
// (vanilla HTML/CSS/JS, no build step) embedded in the gateway binary. It
// reads the /api/requests and /api/costs endpoints served by pkg/proxy.
//
// This is the §6 "Dashboard MVP": Requests / Sessions, Costs, and Tools views.
// A future Next.js app can replace the static assets here; the API surface it
// consumes is already in place.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html app.js edge_features.js edge_admin.html edge_admin.js edge_admin.css style.css brand.css icons.js
var assets embed.FS

// Handler returns an http.Handler serving the dashboard SPA.
func Handler() http.Handler {
	return http.FileServer(http.FS(assets))
}

// FS exposes the embedded assets (useful for tests / debugging).
func FS() fs.FS { return assets }
