package access

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPolicyDefaultsAndRecursiveObjects(t *testing.T) {
	for _, test := range []struct {
		name, yaml string
		allowed    []Permission
	}{
		{"all", "true", permissions},
		{"none", "false", nil},
		{"empty", "{}", nil},
		{"metrics", "metrics: true", []Permission{MetricsRead}},
		{"sessions", "sessions: true", []Permission{SessionsRead, SessionsDisconnect, SessionsDispose}},
		{"session-read", "sessions: {read: true}", []Permission{SessionsRead}},
		{"credentials-only", "flows: {credentials: true}", []Permission{FlowsCredentials}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var policy Policy
			require.NoError(t, yaml.Unmarshal([]byte(test.yaml), &policy))
			for _, p := range permissions {
				allowed, err := policy.Allows(p, nil)
				require.NoError(t, err)
				want := false
				for _, selected := range test.allowed {
					want = want || selected == p
				}
				require.Equal(t, want, allowed, p)
			}
			encoded, err := yaml.Marshal(policy)
			require.NoError(t, err)
			var restored Policy
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, policy.IsEqualTo(restored))
		})
	}
	for _, p := range permissions {
		allowed, err := (Policy{}).Allows(p, nil)
		require.NoError(t, err)
		require.Equal(t, defaultAllowed(p), allowed, p)
	}
	allowed, err := Constant(true).Allows("unknown.permission", nil)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestPolicyStrictTemplatesAtEveryLevel(t *testing.T) {
	for _, source := range []string{
		`'{{ .allowed }}'`,
		`metrics: '{{ .allowed }}'`,
		`metrics: {read: '{{ .allowed }}'}`,
	} {
		var policy Policy
		require.NoError(t, yaml.Unmarshal([]byte(source), &policy))
		for _, value := range []string{"true", "false", " true \n", "TRUE", "yes", "1", "", "secret-claim", strings.Repeat(" ", 65) + "true"} {
			allowed, err := policy.Allows(MetricsRead, map[string]any{"allowed": value})
			if strings.TrimSpace(value) == "true" && len(value) <= 64 {
				require.NoError(t, err)
				require.True(t, allowed)
			} else {
				require.False(t, allowed)
				if value == "false" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.NotContains(t, err.Error(), "secret-claim")
				}
			}
		}
	}
	var policy Policy
	require.NoError(t, yaml.Unmarshal([]byte(`metrics: true
sessions: '{{ fail "private claim" }}'`), &policy))
	allowed, err := policy.Allows(MetricsRead, nil)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = policy.Allows(SessionsRead, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private claim")
	require.False(t, allowed)
}

func TestPolicyRejectsInvalidShapes(t *testing.T) {
	for _, source := range []string{
		"null", "[]", "1", "flase", "metrics: null", "metrics: []", "metrics: {read: {}}",
		"metric: true", "metrics.read: true", "sessions.disconnect: true", "metrics: {write: true}", "metrics: true\nmetrics: false",
		"sessions: {read: true, read: false}", `metrics: '{{'`, "<<: {metrics: true}",
		"&loop {metrics: *loop}",
	} {
		t.Run(source, func(t *testing.T) {
			var policy Policy
			// yaml.v3 intentionally bypasses custom unmarshalling for null. The
			// enclosing configuration rejects it explicitly before decoding.
			var value yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &value))
			require.Error(t, policy.UnmarshalYAML(value.Content[0]))
		})
	}
}

func TestPolicyWithConstantIsImmutableAndKeepsDefaults(t *testing.T) {
	original := Policy{}
	changed := original.WithConstant(AuditlogsDownload, true).WithConstant(FlowsRead, false)
	allowed, err := original.Allows(AuditlogsDownload, nil)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = changed.Allows(AuditlogsDownload, nil)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = changed.Allows(FlowsCredentials, nil)
	require.NoError(t, err)
	require.False(t, allowed)
	changed = Constant(true).WithConstant(MetricsRead, false)
	encoded, err := json.Marshal(changed)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), `"metrics":{"credentials"`)
	var restored Policy
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	for _, p := range permissions {
		allowed, err := restored.Allows(p, nil)
		require.NoError(t, err)
		require.Equal(t, p != MetricsRead, allowed)
	}
}

func TestPolicyJSONRejectsNullAndPreservesExplicitObjects(t *testing.T) {
	for _, source := range []string{`null`, `{"metrics":null}`, `{"metrics":true,"metrics":false}`, `[]`, `{"unknown":true}`} {
		var policy Policy
		require.Error(t, json.Unmarshal([]byte(source), &policy), source)
	}
	var policy Policy
	require.NoError(t, json.Unmarshal([]byte(`{"metrics":true}`), &policy))
	for _, permission := range Permissions() {
		allowed, err := policy.Allows(permission, nil)
		require.NoError(t, err)
		require.Equal(t, permission == MetricsRead, allowed)
	}
}
