// Package mcpwire holds the MCP JSON-RPC wire helpers shared by the hosted
// MCP gateway and the customer-side edge: canonical request parsing (so the
// bytes we authorize are the bytes we forward) and streamable-HTTP decoding.
package mcpwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CanonicalRequest rejects ambiguous JSON objects, then emits the one JSON
// object used for both authorization and upstream execution. Decoder.Token
// handles escaped key spellings, and UseNumber avoids rounding large IDs.
func CanonicalRequest(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	value, err := readUniqueJSON(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON data")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON-RPC request must be an object")
	}
	if err := exactProtocolKeys(root, "jsonrpc", "id", "method", "params"); err != nil {
		return nil, err
	}
	if params, ok := root["params"].(map[string]any); ok {
		if err := exactProtocolKeys(params, "name", "arguments", "_meta"); err != nil {
			return nil, err
		}
	}
	return json.Marshal(value)
}

func exactProtocolKeys(object map[string]any, names ...string) error {
	for key := range object {
		for _, name := range names {
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("noncanonical JSON-RPC key %q", key)
			}
		}
	}
	return nil
}

func readUniqueJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting too deep")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		seen := map[string]bool{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key must be a string")
			}
			folded := strings.ToLower(key)
			if seen[folded] {
				return nil, fmt.Errorf("duplicate or case-variant JSON key %q", key)
			}
			seen[folded] = true
			value, err := readUniqueJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		_, err := dec.Token() // closing brace
		return object, err
	case '[':
		items := []any{}
		for dec.More() {
			value, err := readUniqueJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		_, err := dec.Token() // closing bracket
		return items, err
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

// DecodeSSE returns the last JSON-RPC message in a streamable-HTTP event
// stream, which is the response to the single request we sent.
func DecodeSSE(data []byte) ([]byte, error) {
	var last []byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			candidate := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if json.Valid(candidate) {
				last = append([]byte(nil), candidate...)
			}
		}
	}
	if last == nil {
		return nil, errors.New("no JSON-RPC response in upstream event stream")
	}
	return last, nil
}
