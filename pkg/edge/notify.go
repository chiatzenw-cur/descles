package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// ApprovalNotifier tells approvers that a call is waiting, by POSTing to a
// webhook the edge administrator configures (Slack incoming webhooks accept
// the payload as is; anything else gets the same JSON). By default the
// message names the tool, agent and approval id and links to /admin/ on the
// edge: the call's arguments stay on the edge unless IncludeArgs is set.
type ApprovalNotifier struct {
	URL         string // webhook, a secret: set via DESCLES_EDGE_APPROVAL_WEBHOOK(_FILE)
	AdminURL    string // how approvers reach this edge, e.g. https://descles.internal
	IncludeArgs bool
	Client      *http.Client
	Logger      *slog.Logger
}

// ValidateWebhook accepts https, or http only for a loopback host.
func ValidateWebhook(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("approval webhook must be an absolute URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return errors.New("approval webhook must use https")
	}
	return nil
}

// Notify sends the notice in the background; delivery failures are logged
// and never affect the call (which is already held for approval).
func (n *ApprovalNotifier) Notify(a Approval) {
	if n == nil || n.URL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.send(ctx, a); err != nil && n.Logger != nil {
			n.Logger.Warn("approval notification not delivered", "approval", a.ID, "err", err)
		}
	}()
}

func (n *ApprovalNotifier) payload(a Approval) map[string]any {
	link := "/admin/"
	if n.AdminURL != "" {
		link = n.AdminURL + "/admin/"
	}
	text := fmt.Sprintf("Approval needed: agent %s wants to run %s (approval %s). Decide by %s at %s",
		a.AgentID, a.Tool, a.ID, a.ExpiresAt.Local().Format("15:04"), link)
	detail := map[string]any{"approval_id": a.ID, "tool": a.Tool, "agent_id": a.AgentID, "edge_id": a.EdgeID,
		"expires_at": a.ExpiresAt, "args_sha256": a.ArgsDigest, "admin_url": link}
	if n.IncludeArgs && len(a.Args) > 0 {
		detail["args"] = json.RawMessage(a.Args)
		text += "\nArguments: " + string(a.Args)
	}
	return map[string]any{"text": text, "descles": detail}
}

func (n *ApprovalNotifier) send(ctx context.Context, a Approval) error {
	body, _ := json.Marshal(n.payload(a))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}
