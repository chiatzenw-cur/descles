package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// yamlToJSON bridges a YAML document to JSON so the existing json-tagged
// policy structs parse unchanged. yaml.v3 decodes maps as map[string]any,
// which json.Marshal re-encodes with the same keys; numbers, bools and strings
// survive the round-trip. JSON is a subset of YAML, but we never rely on that
// here — we route every document through one canonical path.
func yamlToJSON(b []byte) ([]byte, error) {
	var obj any
	if err := yaml.Unmarshal(b, &obj); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("yaml->json: %w", err)
	}
	return out, nil
}

// FromYAML parses a YAML policy document.
func FromYAML(raw string) (*Policy, error) {
	j, err := yamlToJSON([]byte(raw))
	if err != nil {
		return nil, err
	}
	return FromJSON(string(j))
}

// Load parses a policy document that may be JSON or YAML. Detection is
// JSON-first (empty input is allow-all), falling back to YAML on a JSON parse
// error.
func Load(raw string) (*Policy, error) {
	if p, err := FromJSON(raw); err == nil {
		return p, nil
	}
	return FromYAML(raw)
}

// LoadFile reads a policy document from path (JSON or YAML) and parses it.
func LoadFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Load(string(b))
}

// ParseUnifiedYAML parses a unified (model/capability/resource) YAML policy.
func ParseUnifiedYAML(raw string) (*Unified, error) {
	j, err := yamlToJSON([]byte(raw))
	if err != nil {
		return nil, err
	}
	return ParseUnified(string(j))
}

// LoadUnified parses a unified policy document that may be JSON or YAML.
func LoadUnified(raw string) (*Unified, error) {
	if u, err := ParseUnified(raw); err == nil {
		return u, nil
	}
	return ParseUnifiedYAML(raw)
}
