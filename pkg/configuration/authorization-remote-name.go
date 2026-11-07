package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/template"
)

var DefaultAuthorizationRemoteName = template.MustNewString("{{.remote.user}}")

func validateAuthorizationRemoteName(value template.String) error {
	if value.IsZero() {
		return nil // Programmatic zero-value configurations retain identity mapping.
	}
	if value.IsHardCoded() {
		if err := (authentication.Identity{Principal: value.String(), Issuer: "remoteName", Subject: value.String()}).Validate(); err != nil {
			return fmt.Errorf("remoteName must produce a valid, nonempty account name")
		}
	}
	return value.Validate()
}

func validateAuthorizationRemoteNameYAML(node *yaml.Node) error {
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	if value, exists := fields["remoteName"]; exists {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
			return reportYamlRelatedErrf(&value, "[remoteName] must be a nonempty string template")
		}
	}
	return nil
}
