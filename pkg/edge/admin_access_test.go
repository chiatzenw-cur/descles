package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminAccessPersistsOnlyHashesAndEnforcesRoles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	access, err := OpenAdminAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := access.Issue("alice", "Alice", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, err := access.Issue("bob", "Bob", "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(viewer)) || bytes.Contains(raw, []byte(adminToken)) {
		t.Fatal("console tokens must never be persisted in plaintext")
	}
	access, err = OpenAdminAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := access.Resolve(viewer); !ok || id.ID != "alice" || id.Role != "viewer" {
		t.Fatalf("viewer resolution: %+v %t", id, ok)
	}
	if _, ok := access.Resolve("wrong"); ok {
		t.Fatal("unexpected token accepted")
	}
	store, err := OpenApprovals(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a := &ApprovalAdmin{Store: store, Token: "owner-secret", Access: access}
	mux := http.NewServeMux()
	a.Register(mux)
	call := func(token, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}
	if r := call(viewer, "GET", "/admin/me", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"id":"alice"`) {
		t.Fatalf("personal identity: %d %s", r.Code, r.Body.String())
	}
	if r := call(viewer, "POST", "/admin/approvals/id/approve", `{}`); r.Code != http.StatusForbidden {
		t.Fatalf("viewer mutation: %d", r.Code)
	}
	if r := call(adminToken, "POST", "/admin/operators", `{"ID":"eve","Name":"Eve","Role":"admin"}`); r.Code != http.StatusForbidden {
		t.Fatalf("non-owner access grant: %d", r.Code)
	}
	if r := call("owner-secret", "GET", "/admin/operators", ""); r.Code != 200 {
		t.Fatalf("owner list: %d", r.Code)
	} else {
		var result map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil || len(result["users"].([]any)) != 3 {
			t.Fatalf("users response: %s %v", r.Body.String(), err)
		}
	}
	if err := access.Revoke("alice"); err != nil {
		t.Fatal(err)
	}
	if r := call(viewer, "GET", "/admin/me", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", r.Code)
	}
}
