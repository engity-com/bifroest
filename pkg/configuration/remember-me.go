package configuration

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type RememberMe string

const (
	RememberMeForbidden                  RememberMe = "forbidden"
	RememberMeAllowed                    RememberMe = "allowed"
	RememberMeAllowedAndEnabledByDefault RememberMe = "allowedAndEnabledByDefault"
	RememberMeEnforced                   RememberMe = "enforced"
)

func (v RememberMe) String() string {
	if v == "" {
		return string(RememberMeForbidden)
	}
	return string(v)
}

func (v RememberMe) Allowed() bool {
	return v == RememberMeAllowed || v == RememberMeAllowedAndEnabledByDefault || v == RememberMeEnforced
}
func (v RememberMe) EnabledByDefault() bool {
	return v == RememberMeAllowedAndEnabledByDefault || v == RememberMeEnforced
}
func (v RememberMe) Validate() error {
	switch v {
	case "", RememberMeForbidden, RememberMeAllowed, RememberMeAllowedAndEnabledByDefault, RememberMeEnforced:
		return nil
	default:
		return fmt.Errorf("invalid rememberMe value %q", v)
	}
}

func (v *RememberMe) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("rememberMe must be a scalar")
	}
	switch strings.ToLower(strings.TrimSpace(node.Value)) {
	case "", "forbidden", "false", "off", "no", "0":
		*v = RememberMeForbidden
	case "allowed", "true", "on", "yes", "1":
		*v = RememberMeAllowed
	case "allowedandenabledbydefault":
		*v = RememberMeAllowedAndEnabledByDefault
	case "enforced":
		*v = RememberMeEnforced
	default:
		return fmt.Errorf("invalid rememberMe value %q", node.Value)
	}
	return nil
}

func (v RememberMe) MarshalYAML() (any, error) { return v.String(), v.Validate() }

// Enabled interprets a client's preference; it never expands server policy.
func (v RememberMe) Enabled(preference string, present bool) bool {
	if !v.Allowed() {
		return false
	}
	if v == RememberMeEnforced {
		return true
	}
	if !present {
		return v.EnabledByDefault()
	}
	switch strings.ToLower(strings.TrimSpace(preference)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}
