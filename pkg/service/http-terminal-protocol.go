package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/terminal"
)

const webTerminalProtocol = "bifroest-terminal.v1"

type webTerminalOpen struct {
	slug, token, command string
	exec                 bool
	pty                  terminal.Pty
	hasPty               bool
	environment          []string
}

// Typed, exact field sets avoid encoding/json's case-insensitive struct fields,
// duplicate keys, null defaults and trailing values. Nested PTY is parsed by the
// same rule; no generic object can become a connection/session/authorization.
func webTerminalObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8 control message")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("control object required")
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("invalid field")
		}
		known := false
		for _, candidate := range allowed {
			known = known || name == candidate
		}
		if !known {
			return nil, fmt.Errorf("unknown field")
		}
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(value, []byte("null")) {
			return nil, fmt.Errorf("null field")
		}
		values[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing control data")
	}
	return values, nil
}

func webTerminalString(values map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, present := values[name]
	if !present {
		if required {
			return "", fmt.Errorf("missing field")
		}
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("string field required")
	}
	return value, nil
}

func parseWebTerminalOpen(raw []byte) (webTerminalOpen, error) {
	values, err := webTerminalObject(raw, "type", "slug", "accessToken", "task", "command", "pty", "environment")
	if err != nil {
		return webTerminalOpen{}, err
	}
	var open webTerminalOpen
	kind, err := webTerminalString(values, "type", true)
	if err != nil || kind != "open" {
		return open, fmt.Errorf("open message required")
	}
	if open.slug, err = webTerminalString(values, "slug", true); err != nil {
		return open, err
	}
	if open.token, err = webTerminalString(values, "accessToken", true); err != nil {
		return open, err
	}
	task, err := webTerminalString(values, "task", true)
	if err != nil {
		return open, err
	}
	switch task {
	case "shell":
		if _, present := values["command"]; present {
			return open, fmt.Errorf("shell cannot specify a command")
		}
	case "exec":
		open.exec = true
		if open.command, err = webTerminalString(values, "command", true); err != nil {
			return open, err
		}
	default:
		return open, fmt.Errorf("unsupported execution task")
	}
	if len(open.command) > 4096 || strings.ContainsRune(open.command, 0) {
		return open, fmt.Errorf("invalid command")
	}
	if raw, present := values["pty"]; present {
		pty, err := webTerminalObject(raw, "term", "columns", "rows", "widthPixels", "heightPixels")
		if err != nil {
			return open, err
		}
		if open.pty.Term, err = webTerminalString(pty, "term", true); err != nil {
			return open, err
		}
		if len(open.pty.Term) == 0 || len(open.pty.Term) > 128 || strings.ContainsFunc(open.pty.Term, func(r rune) bool {
			allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '+'
			return !allowed
		}) {
			return open, fmt.Errorf("invalid terminal type")
		}
		if open.pty.Window, err = parseWebTerminalWindow(pty); err != nil {
			return open, err
		}
		open.hasPty = true
	}
	if raw, present := values["environment"]; present {
		var entries []json.RawMessage
		if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &entries) != nil || len(entries) > 32 {
			return open, fmt.Errorf("invalid client environment")
		}
		seen := make(map[string]bool)
		total := 0
		for _, entry := range entries {
			var value string
			if len(entry) == 0 || entry[0] != '"' || json.Unmarshal(entry, &value) != nil {
				return open, fmt.Errorf("invalid client environment entry")
			}
			total += len(value)
			name, content, ok := strings.Cut(value, "=")
			if !ok || len(name) == 0 || len(name) > 128 || len(content) > 2048 || total > 8<<10 || strings.ContainsRune(value, 0) || seen[strings.ToUpper(name)] {
				return open, fmt.Errorf("invalid client environment entry")
			}
			for index, r := range name {
				allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || index > 0 && r >= '0' && r <= '9'
				if !allowed {
					return open, fmt.Errorf("invalid client environment name")
				}
			}
			seen[strings.ToUpper(name)] = true
			open.environment = append(open.environment, value)
		}
	}
	return open, nil
}

func parseWebTerminalWindow(values map[string]json.RawMessage) (terminal.Window, error) {
	var window terminal.Window
	for _, field := range []struct {
		name     string
		target   *int
		required bool
	}{{"columns", &window.Width, true}, {"rows", &window.Height, true}, {"widthPixels", &window.WidthPixels, false}, {"heightPixels", &window.HeightPixels, false}} {
		raw, exists := values[field.name]
		if !exists {
			if field.required {
				return window, fmt.Errorf("missing window field")
			}
			continue
		}
		if err := json.Unmarshal(raw, field.target); err != nil {
			return window, fmt.Errorf("integer window field required")
		}
	}
	if err := validateTerminalWindow(window); err != nil {
		return window, err
	}
	if window.Width == 0 || window.Height == 0 {
		return window, fmt.Errorf("positive terminal dimensions required")
	}
	return window, nil
}
