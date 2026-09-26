package edge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModelAliases(t *testing.T) {
	aliases, err := ParseModelAliases("deepseek-v4-flash=deepseek-flash, claude-sonnet-4-5 = deepseek-v4-pro")
	if err != nil || len(aliases) != 2 {
		t.Fatalf("%v %v", aliases, err)
	}
	for _, bad := range []string{"a", "a=", "a=a", "a=b,a=c", "a=b,b=c"} {
		if _, err := ParseModelAliases(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var seen []byte
	var requested string
	h := AliasModels(aliases, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		requested = r.Header.Get("X-Descles-Requested-Model")
	}))
	body := `{"model":"deepseek-v4-flash","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	if !bytes.Contains(seen, []byte(`"model":"deepseek-flash"`)) || !bytes.Contains(seen, []byte(`"stream":true`)) || requested != "deepseek-v4-flash" {
		t.Fatalf("rewrite: %s (requested %q)", seen, requested)
	}
	for _, passthrough := range []string{`{"model":"other"}`, `not json`, `{"model":42}`} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(passthrough)))
		if string(seen) != passthrough {
			t.Fatalf("must pass %q through unchanged, got %q", passthrough, seen)
		}
	}
}
