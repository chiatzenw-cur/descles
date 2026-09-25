package connect

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	codexBegin = "# >>> descles (managed by `descles connect codex`; edits inside are replaced) >>>"
	codexEnd   = "# <<< descles <<<"
)

// CodexConfig adds (or replaces) a managed block in ~/.codex/config.toml:
// a "descles" model provider pointing at the edge, a "descles" profile that
// selects it, and one MCP server per edge connector. Everything is inside
// tables, so appending never changes the meaning of the user's own top-level
// keys. The key is read from DESCLES_AGENT_KEY at run time, never written.
//
// Run with: codex --profile descles
func CodexConfig(existing, edgeURL, model string, connectors []string) string {
	var b strings.Builder
	b.WriteString(codexBegin + "\n")
	b.WriteString("[model_providers.descles]\n")
	b.WriteString("name = \"Descles edge\"\n")
	b.WriteString("base_url = " + strconv.Quote(edgeURL+"/v1") + "\n")
	b.WriteString("env_key = \"DESCLES_AGENT_KEY\"\n")
	b.WriteString("wire_api = \"responses\"\n\n")
	b.WriteString("[profiles.descles]\n")
	b.WriteString("model_provider = \"descles\"\n")
	if model != "" {
		b.WriteString("model = " + strconv.Quote(model) + "\n")
	}
	for _, c := range connectors {
		fmt.Fprintf(&b, "\n[mcp_servers.%s]\n", strconv.Quote("descles-"+c))
		b.WriteString("url = " + strconv.Quote(edgeURL+"/mcp/"+c) + "\n")
		b.WriteString("bearer_token_env_var = \"DESCLES_AGENT_KEY\"\n")
	}
	b.WriteString(codexEnd + "\n")
	block := b.String()

	if i := strings.Index(existing, codexBegin); i >= 0 {
		if j := strings.Index(existing[i:], codexEnd); j >= 0 {
			end := i + j + len(codexEnd)
			if end < len(existing) && existing[end] == '\n' {
				end++
			}
			return existing[:i] + block + existing[end:]
		}
	}
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	if existing != "" {
		existing += "\n"
	}
	return existing + block
}

// OpenAIInstructions is the generic setup for any OpenAI-compatible agent
// (Hermes, custom agents, SDK scripts): point the base URL at the edge and
// the MCP servers at the edge's connectors.
func OpenAIInstructions(edgeURL string, connectors []string) string {
	var b strings.Builder
	b.WriteString("Model traffic (OpenAI-compatible: chat completions and responses):\n")
	b.WriteString("  OPENAI_BASE_URL=" + edgeURL + "/v1\n")
	b.WriteString("  OPENAI_API_KEY=$DESCLES_AGENT_KEY   (your agent key, not a provider key)\n")
	b.WriteString("Anthropic-compatible clients: base URL " + edgeURL + "/anthropic\n")
	if len(connectors) > 0 {
		b.WriteString("\nMCP servers (streamable HTTP, header Authorization: Bearer $DESCLES_AGENT_KEY):\n")
		for _, c := range connectors {
			b.WriteString("  descles-" + c + "  " + edgeURL + "/mcp/" + c + "\n")
		}
	}
	b.WriteString("\nNative tools: if the agent runs shell or file tools itself, call\n")
	b.WriteString("  POST " + edgeURL + "/v1/tool-check  {\"client\":\"<name>\",\"tool\":\"<tool>\",\"input\":{...}}\n")
	b.WriteString("before executing (decision: allow | deny | require_approval), and\n")
	b.WriteString("  POST " + edgeURL + "/v1/tool-report {\"client\":\"<name>\",\"tool\":\"<tool>\",\"outcome\":\"ok|error\"}\n")
	b.WriteString("after, or expose those tools through an edge MCP connector instead.\n")
	return b.String()
}
