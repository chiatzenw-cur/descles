package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

func TestKeyringBindsAgentWithoutStoringPlaintext(t *testing.T) {
	key := "dsk_customer_agent_secret"
	hash := sha256.Sum256([]byte(key))
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`[ {"key_sha256":"`+hex.EncodeToString(hash[:])+`","org_id":"org_1","agent_id":"agent_1"} ]`), 0600); err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if org, _, agent, ok := ring.Resolve(key); !ok || org != "org_1" || agent != "agent_1" {
		t.Fatalf("wrong key binding: %q %q %t", org, agent, ok)
	}
	if _, _, _, ok := ring.Resolve("not-the-key"); ok {
		t.Fatal("unknown key accepted")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), key) {
		t.Fatal("plaintext key written to disk")
	}
}

func TestMetadataOutboxRetriesWithoutContent(t *testing.T) {
	ctx := context.Background()
	queue, err := OpenOutbox(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := &MeteredStore{Storage: storage.NewMemory(), Outbox: queue, EdgeID: "edge_1"}
	defer store.Close()
	now := time.Now().UTC()
	span := &tracing.Span{SpanID: "s1", TraceID: "t1", AgentID: "agent_1", SpanType: tracing.SpanTypeLLM, StartedAt: now, EndedAt: now.Add(time.Millisecond), Status: tracing.StatusOK,
		Attributes: map[string]any{tracing.AttrModel: "test-model", tracing.AttrInputToks: 12, tracing.AttrOutputToks: 3, tracing.AttrCostUSD: 0.01, "prompt": "private prompt", "provider_api_key": "sk-secret", "tool_arguments": "private args"}}
	if err := store.PutSpan(ctx, span); err != nil {
		t.Fatal(err)
	}
	m, ok, err := queue.Next(ctx)
	if err != nil || !ok {
		t.Fatalf("queued metadata: %+v %t %v", m, ok, err)
	}
	if !m.UsageKnown {
		t.Fatal("provider-reported token usage marked unknown")
	}
	raw, _ := json.Marshal(m)
	for _, secret := range []string{"private prompt", "sk-secret", "private args"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("metadata leaked %q", secret)
		}
	}
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer edge-report-key" {
			t.Error("wrong report token")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	reporter := &Reporter{Outbox: queue, URL: srv.URL, Token: "edge-report-key"}
	if _, err := reporter.Flush(ctx, 10); err == nil {
		t.Fatal("expected retryable failure")
	}
	if pending, _ := queue.Count(ctx); pending != 1 {
		t.Fatalf("pending after failure = %d", pending)
	}
	if sent, err := reporter.Flush(ctx, 10); err != nil || sent != 1 {
		t.Fatalf("retry sent=%d err=%v", sent, err)
	}
	if pending, _ := queue.Count(ctx); pending != 0 {
		t.Fatalf("pending after ack = %d", pending)
	}
}
