// Package identity parses optional Descles metadata headers so a request can be
// attributed to a user, agent, session and trace without requiring every
// application to change its code — the existing OpenAI client just sends a
// few extra headers.
package identity

import (
	"net/http"
	"strings"
)

// Header names Descles reads from inbound requests.
const (
	HeaderUser    = "X-Descles-User"
	HeaderAgent   = "X-Descles-Agent"
	HeaderSession = "X-Descles-Session"
	HeaderTrace   = "X-Descles-Trace"
	// HeaderPlaybook carries the playbook/config version, e.g.
	// "engineering-default@2026-09-26.1" or "v3+sha256:ab12...".
	HeaderPlaybook = "X-Descles-Playbook-Version"
	HeaderOrg      = "X-Descles-Org"
	HeaderProject  = "X-Descles-Project"
)

// Identity is the optional client-supplied attribution for a request.
// Fields are parsed from headers; the gateway also generates a trace/session
// id when the client does not provide one.
type Identity struct {
	OrganizationID string
	ProjectID      string
	UserID         string
	AgentID        string
	SessionID      string
	TraceID        string
	// PlaybookVersion names the agent configuration (skills, context, model,
	// tools) a request was made under, so evaluations can group by it.
	PlaybookVersion string
}

// FromHeaders reads the X-Descles-* family of headers. None are required; the
// gateway works in metadata-only mode when they are absent.
func FromHeaders(h http.Header) Identity {
	return Identity{
		OrganizationID:  h.Get(HeaderOrg),
		ProjectID:       h.Get(HeaderProject),
		UserID:          h.Get(HeaderUser),
		AgentID:         h.Get(HeaderAgent),
		SessionID:       h.Get(HeaderSession),
		TraceID:         h.Get(HeaderTrace),
		PlaybookVersion: CleanPlaybookVersion(h.Get(HeaderPlaybook)),
	}
}

// CleanPlaybookVersion accepts a version label of 1-120 characters from
// letters, digits and . _ - : @ + / and drops anything else, so the label
// cannot carry free text into records.
func CleanPlaybookVersion(v string) string {
	if v == "" || len(v) > 120 {
		return ""
	}
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._-:@+/", c)) {
			return ""
		}
	}
	return v
}
