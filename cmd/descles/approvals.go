package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/connect"
)

// runApprovals: descles approvals list|approve|deny [id] --edge URL --admin-token-file PATH [--by NAME] [--reason TEXT]
func runApprovals(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: descles approvals list | approve <id> | deny <id>  --edge URL --admin-token-file PATH [--by NAME] [--reason TEXT]")
	}
	action, rest := args[0], args[1:]
	var id string
	if action == "approve" || action == "deny" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return fmt.Errorf("%s needs an approval id", action)
		}
		id, rest = rest[0], rest[1:]
	} else if action != "list" {
		return fmt.Errorf("unknown approvals action %q", action)
	}
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	edgeURL := fs.String("edge", os.Getenv("DESCLES_EDGE_URL"), "edge base URL")
	tokenFile := fs.String("admin-token-file", "", "file holding the edge admin token (or set DESCLES_EDGE_ADMIN_TOKEN)")
	by := fs.String("by", os.Getenv("USER"), "your name, recorded with the decision")
	reason := fs.String("reason", "", "reason recorded with the decision")
	state := fs.String("state", "pending", "list: pending, approved, denied, used, expired or all")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	base, err := connect.NormalizeURL(*edgeURL)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(os.Getenv("DESCLES_EDGE_ADMIN_TOKEN"))
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return errors.New("edge admin token required (--admin-token-file or DESCLES_EDGE_ADMIN_TOKEN)")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	do := func(method, path string, body any) ([]byte, error) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, base+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("edge: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		return data, nil
	}
	if action == "list" {
		q := "/admin/approvals"
		if *state != "all" {
			q += "?state=" + *state
		}
		data, err := do(http.MethodGet, q, nil)
		if err != nil {
			return err
		}
		var out struct {
			Approvals []struct {
				ID        string          `json:"id"`
				Tool      string          `json:"tool"`
				AgentID   string          `json:"agent_id"`
				State     string          `json:"state"`
				Args      json.RawMessage `json:"args"`
				CreatedAt time.Time       `json:"created_at"`
				ExpiresAt time.Time       `json:"expires_at"`
				DecidedBy string          `json:"decided_by"`
			} `json:"approvals"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return err
		}
		if len(out.Approvals) == 0 {
			fmt.Println("no approvals in state", *state)
			return nil
		}
		for _, a := range out.Approvals {
			fmt.Printf("%s  %-8s %s  agent=%s  expires=%s", a.ID, a.State, a.Tool, a.AgentID, a.ExpiresAt.Local().Format("15:04"))
			if a.DecidedBy != "" {
				fmt.Printf("  by=%s", a.DecidedBy)
			}
			fmt.Println()
			if len(a.Args) > 0 {
				var pretty bytes.Buffer
				if json.Indent(&pretty, a.Args, "    ", "  ") == nil {
					fmt.Println("    " + pretty.String())
				}
			}
		}
		return nil
	}
	if strings.TrimSpace(*by) == "" {
		return errors.New("--by is required: decisions are recorded with a name")
	}
	if _, err := do(http.MethodPost, "/admin/approvals/"+id+"/"+action, map[string]string{"by": *by, "reason": *reason}); err != nil {
		return err
	}
	if action == "approve" {
		fmt.Printf("%s approved: the agent's next identical call runs once\n", id)
	} else {
		fmt.Printf("%s denied: the call will not run\n", id)
	}
	return nil
}
