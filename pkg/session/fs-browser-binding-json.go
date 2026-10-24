package session

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/authentication"
)

// Exact field names/types and duplicate/null/UTF16/trailing-data rejection must
// precede struct decoding, which alone matches case-insensitively and tolerates
// duplicate keys and replacement characters. Nested identity gets the same rule.
func browserBindingObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidBrowserBinding
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrInvalidBrowserBinding
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidBrowserBinding
		}
		name, ok := key.(string)
		if !ok {
			return nil, ErrInvalidBrowserBinding
		}
		known := false
		for _, candidate := range allowed {
			known = known || name == candidate
		}
		if !known {
			return nil, ErrInvalidBrowserBinding
		}
		if _, exists := fields[name]; exists {
			return nil, ErrInvalidBrowserBinding
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalidBrowserBinding
		}
		if bytes.Equal(value, []byte("null")) || len(value) == 0 {
			return nil, ErrInvalidBrowserBinding
		}
		if value[0] == '"' && !associationStringScalarsValid(value) {
			return nil, ErrInvalidBrowserBinding
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrInvalidBrowserBinding
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidBrowserBinding
	}
	return fields, nil
}

func decodeBrowserBindings(raw []byte, flow, id string) ([]BrowserBinding, error) {
	if len(raw) > maximumBrowserBindingsBytes {
		return nil, ErrInvalidBrowserBinding
	}
	root, err := browserBindingObject(raw, "schema", "flow", "sessionId", "bindings")
	if err != nil || len(root) != 4 {
		return nil, ErrInvalidBrowserBinding
	}
	var schema string
	if json.Unmarshal(root["schema"], &schema) != nil || schema != browserBindingsSchema {
		return nil, ErrInvalidBrowserBinding
	}
	var storedFlow, storedID string
	if json.Unmarshal(root["flow"], &storedFlow) != nil || json.Unmarshal(root["sessionId"], &storedID) != nil || storedFlow != flow || storedID != id {
		return nil, ErrInvalidBrowserBinding
	}
	var entries []json.RawMessage
	if len(root["bindings"]) == 0 || root["bindings"][0] != '[' || json.Unmarshal(root["bindings"], &entries) != nil || len(entries) > MaximumBrowserBindings {
		return nil, ErrInvalidBrowserBinding
	}
	result := make([]BrowserBinding, 0, len(entries))
	seen := make(map[string]bool)
	for _, raw := range entries {
		fields, err := browserBindingObject(raw, "id", "origin", "slug", "identity", "target", "user", "publicKey", "revision", "createdAt", "lastUsedAt", "expiresAt", "credential")
		if err != nil || len(fields) < 11 {
			return nil, ErrInvalidBrowserBinding
		}
		for _, required := range []string{"id", "origin", "slug", "identity", "target", "user", "publicKey", "revision", "createdAt", "lastUsedAt", "expiresAt"} {
			if _, present := fields[required]; !present {
				return nil, ErrInvalidBrowserBinding
			}
		}
		if credential, present := fields["credential"]; present {
			values, err := browserBindingObject(credential, "kind", "method", "publicKey")
			if err != nil || len(values) < 2 {
				return nil, ErrInvalidBrowserBinding
			}
			var stored authentication.SessionCredential
			if json.Unmarshal(credential, &stored) != nil || stored.Validate() != nil {
				return nil, ErrInvalidBrowserBinding
			}
		}
		identity, err := browserBindingObject(fields["identity"], "principal", "issuer", "subject")
		if err != nil || len(identity) == 0 {
			return nil, ErrInvalidBrowserBinding
		}
		var binding BrowserBinding
		if json.Unmarshal(raw, &binding) != nil || binding.Validate() != nil || seen[binding.ID] {
			return nil, ErrInvalidBrowserBinding
		}
		seen[binding.ID] = true
		result = append(result, binding)
	}
	return result, nil
}
