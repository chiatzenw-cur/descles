// Package provider implements the upstream OpenAI-compatible transport and
// the token/usage parsing that lets Descles account for what the model did.
//
// Descles reads the client's Authorization header only as a project key and
// discards it; the real provider credential is configured separately and is
// injected here. Provider error responses are passed through verbatim.
package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Upstream is the configured LLM provider this gateway proxies to.
type Upstream struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// httpClient returns the configured client. The fallback is not assigned back
// to Upstream: registries are shared across requests, and a lazy write here
// would race when the first calls arrive concurrently.
func (u *Upstream) httpClient() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return NoRedirectClient(120 * time.Second)
}

// noRedirectClient builds an outbound client that refuses to follow HTTP
// redirects. Redirects after the firewall check could silently retarget an
// approved host to an internal one (SSRF); LLM providers never need them.
func NoRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("upstream redirects are not followed (possible SSRF retarget)")
		},
	}
}

// NewRequest builds an outbound POST request to path (e.g. "/chat/completions")
// with the configured upstream credential. body is the raw JSON the client
// sent.
func (u *Upstream) NewRequest(ctx context.Context, path string, body []byte) (*http.Request, error) {
	base := strings.TrimRight(u.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if u.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.APIKey)
	}
	return req, nil
}

// Do performs the round trip.
func (u *Upstream) Do(req *http.Request) (*http.Response, error) {
	return u.httpClient().Do(req)
}

// ProviderName derives a short upstream label from the base URL, e.g.
// "https://api.deepseek.com/v1" -> "deepseek".
func ProviderName(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case strings.Contains(host, "openrouter"):
		return "openrouter"
	case strings.Contains(host, "openai"):
		return "openai"
	case strings.Contains(host, "deepseek"):
		return "deepseek"
	case strings.Contains(host, "anthropic"):
		return "anthropic"
	case strings.Contains(host, "generativelanguage"):
		return "gemini"
	case strings.Contains(host, "moonshot"):
		return "moonshot"
	case strings.Contains(host, "zhipu"):
		return "zhipu"
	default:
		return host
	}
}

// Usage is the normalised token accounting for a single request.
// InputTokens EXCLUDES CachedTokens on both wires: OpenAI's prompt_tokens
// include the cached subset while Anthropic's input_tokens do not, so the two
// are normalised here — pricing and display then mean one thing everywhere.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
	CachedTokens int `json:"cached_tokens"`
}

type chatUsage struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	TotalTokens         int `json:"total_tokens"`
	PromptTokensDetails struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

type responsesUsage struct {
	InputTokens        int `json:"input_tokens"`
	OutputTokens       int `json:"output_tokens"`
	TotalTokens        int `json:"total_tokens"`
	InputTokensDetails struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

type chatChoice struct {
	Message struct {
		ToolCalls []json.RawMessage `json:"tool_calls"`
	} `json:"message"`
}

type toolCallJSON struct {
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

type chatCompletion struct {
	Model   string       `json:"model"`
	Usage   *chatUsage   `json:"usage"`
	Choices []chatChoice `json:"choices"`
}

type responseItem struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type responsesBody struct {
	Model  string          `json:"model"`
	Usage  *responsesUsage `json:"usage"`
	Output []responseItem  `json:"output"`
}

// ChatResult is the parsed outcome of a non-streaming chat completion.
type ChatResult struct {
	Model         string
	Usage         Usage
	ToolCallCount int
	// ToolNames lists the names of the tool calls the model requested (for
	// policy and audit).
	ToolNames []string
}

// ParseChatCompletion parses a non-streaming /chat/completions response body.
func ParseChatCompletion(body []byte) (ChatResult, error) {
	var resp chatCompletion
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChatResult{}, fmt.Errorf("parse chat completion: %w", err)
	}
	res := ChatResult{Model: resp.Model}
	if resp.Usage != nil {
		res.Usage = Usage{
			InputTokens:  UncachedInput(resp.Usage.PromptTokens, resp.Usage.PromptTokensDetails.CachedTokens),
			OutputTokens: resp.Usage.CompletionTokens,
			TotalTokens:  resp.Usage.TotalTokens,
			CachedTokens: resp.Usage.PromptTokensDetails.CachedTokens,
		}
	}
	for _, c := range resp.Choices {
		res.ToolCallCount += len(c.Message.ToolCalls)
		for _, raw := range c.Message.ToolCalls {
			var tc toolCallJSON
			if json.Unmarshal(raw, &tc) == nil && tc.Function.Name != "" {
				res.ToolNames = append(res.ToolNames, tc.Function.Name)
			}
		}
	}
	return res, nil
}

// ParseResponses parses a non-streaming /v1/responses response body.
func ParseResponses(body []byte) (ChatResult, error) {
	var resp responsesBody
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChatResult{}, fmt.Errorf("parse responses: %w", err)
	}
	res := ChatResult{Model: resp.Model}
	if resp.Usage != nil {
		res.Usage = Usage{
			InputTokens:  UncachedInput(resp.Usage.InputTokens, resp.Usage.InputTokensDetails.CachedTokens),
			OutputTokens: resp.Usage.OutputTokens,
			TotalTokens:  resp.Usage.TotalTokens,
			CachedTokens: resp.Usage.InputTokensDetails.CachedTokens,
		}
	}
	for _, it := range resp.Output {
		if it.Type == "function_call" {
			res.ToolCallCount++
			if it.Name != "" {
				res.ToolNames = append(res.ToolNames, it.Name)
			}
		}
	}
	return res, nil
}

// StreamResult captures what a streamed response told us: token usage (if the
// provider emits it), the number of distinct tool calls the model requested,
// and whether the stream ended on a terminal event.
type StreamResult struct {
	Usage         Usage
	ToolCallCount int
	Done          bool
}

type streamState struct {
	usage   Usage
	toolIdx map[int]bool
	done    bool
}

// RelayStream copies an upstream SSE (or NDJSON) stream to dst, flushing
// through the optional flusher, and analyses each data line to extract usage
// and tool-call indexes. It never buffers the whole body, so long and truly
// streaming responses forward with no added latency.
func RelayStream(dst io.Writer, src io.Reader, flusher http.Flusher) (StreamResult, error) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	st := &streamState{toolIdx: map[int]bool{}}

	for scanner.Scan() {
		line := scanner.Text()
		if _, err := io.WriteString(dst, line); err != nil {
			return result(st), err
		}
		if _, err := io.WriteString(dst, "\n"); err != nil {
			return result(st), err
		}
		if flusher != nil {
			flusher.Flush()
		}
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			analyse(payload, st)
		}
	}
	return result(st), scanner.Err()
}

func result(st *streamState) StreamResult {
	return StreamResult{
		Usage:         st.usage,
		ToolCallCount: len(st.toolIdx),
		Done:          st.done,
	}
}

func analyse(payload string, st *streamState) {
	if payload == "" {
		return
	}
	if payload == "[DONE]" {
		st.done = true
		return
	}
	// Try to extract usage (chat top-level "usage", or responses "response.usage").
	if u, ok := extractUsage([]byte(payload)); ok {
		st.usage = u
	}
	// Best-effort tool-call index tracking for chat streaming chunks.
	var chunk struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Index int `json:"index"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(payload), &chunk); err == nil {
		for _, c := range chunk.Choices {
			for _, tc := range c.Delta.ToolCalls {
				st.toolIdx[tc.Index] = true
			}
		}
	}
}

// extractUsage finds a Usage object at the top level or nested under
// response (responses API). A nil/empty usage is not reported.
func extractUsage(payload []byte) (Usage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return Usage{}, false
	}
	if raw, ok := m["usage"]; ok {
		if u, ok := unmarshalUsage(raw); ok {
			return u, true
		}
	}
	if raw, ok := m["response"]; ok {
		var r struct {
			Usage json.RawMessage `json:"usage"`
		}
		if json.Unmarshal(raw, &r) == nil && len(r.Usage) > 0 && string(r.Usage) != "null" {
			if u, ok := unmarshalUsage(r.Usage); ok {
				return u, true
			}
		}
	}
	return Usage{}, false
}

// uncachedInput converts an OpenAI-wire input count into fresh (uncached) input.
//
// OpenAI's prompt_tokens (and the responses API's input_tokens) INCLUDE the
// cached subset, whereas Anthropic reports cache reads as a separate field that
// is not part of input_tokens. Billing "input * input_rate + cached *
// cached_rate" on the OpenAI wire therefore charges the cached tokens twice, at
// full rate — and agent traffic is mostly cache hits, so the error is large.
// Normalising here keeps Usage.InputTokens meaning the same thing on both wires.
// UncachedInput turns an OpenAI-wire input count into fresh (uncached) input for
// the proxy package and for these parsers alike.
func UncachedInput(input, cached int) int {
	if cached > 0 && cached <= input {
		return input - cached
	}
	return input
}

func unmarshalUsage(raw json.RawMessage) (Usage, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return Usage{}, false
	}
	var cu chatUsage
	if err := json.Unmarshal(raw, &cu); err == nil && (cu.PromptTokens != 0 || cu.CompletionTokens != 0) {
		return Usage{
			InputTokens:  UncachedInput(cu.PromptTokens, cu.PromptTokensDetails.CachedTokens),
			OutputTokens: cu.CompletionTokens,
			TotalTokens:  cu.TotalTokens,
			CachedTokens: cu.PromptTokensDetails.CachedTokens,
		}, true
	}
	var ru responsesUsage
	if err := json.Unmarshal(raw, &ru); err == nil && (ru.InputTokens != 0 || ru.OutputTokens != 0) {
		return Usage{
			InputTokens:  UncachedInput(ru.InputTokens, ru.InputTokensDetails.CachedTokens),
			OutputTokens: ru.OutputTokens,
			TotalTokens:  ru.TotalTokens,
			CachedTokens: ru.InputTokensDetails.CachedTokens,
		}, true
	}
	return Usage{}, false
}
