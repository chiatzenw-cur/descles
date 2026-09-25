package proxy

import (
	"bytes"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

func TestDelegatedToolCeilingRewritesAndRecordsDenial(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"github.write":"allow"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(agent, tool string, args map[string]any) bool {
		return tool == "github.read" && args["repo"] == "repo/a"
	}
	buf := []byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"github.write","arguments":"{\"repo\":\"repo/a\"}"}}]}}]}`)
	_, stat := rewriteDeniedToolCalls(buf, "child", "", pol, nil, nil, nil, guard)
	if stat.denied != 1 {
		t.Fatalf("denied=%d", stat.denied)
	}
	notes := proposedToolCalls(buf, "child", "", pol, guard)
	if len(notes) != 1 || notes[0].decision != policy.Deny {
		t.Fatalf("recorded decision=%+v", notes)
	}
	allowed := []byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"github.read","arguments":"{\"repo\":\"repo/a\"}"}}]}}]}`)
	result, stat := rewriteDeniedToolCalls(allowed, "child", "", pol, nil, nil, nil, guard)
	if stat.denied != 0 || !bytes.Equal(result, allowed) {
		t.Fatal("allowed call changed")
	}
}
