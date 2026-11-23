package test

import (
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Lua strings are byte strings, whereas JSON silently replaces malformed UTF-8.
// Reject it before serialization can change identifiers or collapse distinct
// object keys. This includes arbitrary OIDC claims/extras, not just fixed fields.
func validDataEncoding(data any) bool {
	switch value := data.(type) {
	case string:
		return utf8.ValidString(value)
	case map[string]any:
		for key, item := range value {
			if !utf8.ValidString(key) || !validDataEncoding(item) {
				return false
			}
		}
	case []any:
		for _, item := range value {
			if !validDataEncoding(item) {
				return false
			}
		}
	}
	return true
}

// JSON's case-insensitive struct-field matching must not admit property aliases
// that the raw Lua fact validators do not inspect. Derive the exact vocabulary
// from the fixture types' JSON tags, including nested objects and list entries.
// Map keys (flow names) remain data; RawMessage artifacts have their own schema
// validation and must retain arbitrary OIDC claim and OAuth extra keys.
func matchesDataProperties(data any, schema reflect.Type) bool {
	if schema == nil {
		return false
	}
	for schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	if schema == reflect.TypeFor[json.RawMessage]() {
		return true
	}
	switch schema.Kind() {
	case reflect.Struct:
		if fields, ok := data.(map[string]any); ok {
			for name, value := range fields {
				var fieldType reflect.Type
				for index := range schema.NumField() {
					field := schema.Field(index)
					property, _, _ := strings.Cut(field.Tag.Get("json"), ",")
					if property != "" && property != "-" && property == name {
						fieldType = field.Type
						break
					}
				}
				if !matchesDataProperties(value, fieldType) {
					return false
				}
			}
		}
	case reflect.Map:
		if fields, ok := data.(map[string]any); ok {
			for _, value := range fields {
				if !matchesDataProperties(value, schema.Elem()) {
					return false
				}
			}
		}
	case reflect.Slice:
		if items, ok := data.([]any); ok {
			for _, value := range items {
				if !matchesDataProperties(value, schema.Elem()) {
					return false
				}
			}
		}
	}
	// Value types and null eligibility remain the decoder/semantic validators'
	// responsibility; this check only constrains schema property names.
	return true
}
