package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFlowsRejectDuplicateNames(t *testing.T) {
	flows := Flows{{Name: "duplicate"}, {Name: "duplicate"}}
	require.ErrorContains(t, flows.Validate(), "duplicates")
}

func TestFlowsYamlRejectsDuplicateNames(t *testing.T) {
	var flows Flows
	err := yaml.Unmarshal([]byte(`
- name: duplicate
  authorization:
    type: oidcDeviceAuth
    issuer: https://example.org
    clientId: client
    clientSecret: secret
  environment:
    type: local
    name: user
- name: duplicate
  authorization:
    type: oidcDeviceAuth
    issuer: https://example.org
    clientId: client
    clientSecret: secret
  environment:
    type: local
    name: user
`), &flows)
	require.ErrorContains(t, err, "duplicates")
}
