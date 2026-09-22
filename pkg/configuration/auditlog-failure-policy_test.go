package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAuditlogFailurePolicy(t *testing.T) {
	var zero AuditlogFailurePolicy
	require.Equal(t, AuditlogFailurePolicyStrict, zero)
	require.Equal(t, AuditlogFailurePolicyStrict, DefaultAuditlogFailurePolicy)
	require.Equal(t, "strict", zero.String())
	require.NoError(t, zero.Validate())
	require.False(t, zero.IsZero())
	require.True(t, zero.IsEqualTo(AuditlogFailurePolicyStrict))
	require.True(t, zero.IsEqualTo(&zero))
	require.False(t, zero.IsEqualTo(AuditlogFailurePolicyBestEffort))
	require.False(t, zero.IsEqualTo((*AuditlogFailurePolicy)(nil)))
	require.Equal(t, zero, zero.Clone())

	text, err := AuditlogFailurePolicyBestEffort.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "bestEffort", string(text))

	unknown := AuditlogFailurePolicy(255)
	require.ErrorContains(t, unknown.Validate(), "illegal auditlog failure policy")
	require.Error(t, unknown.Set("unknown"))
}

func TestAuditlogFailurePolicyYAML(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    string
		expected AuditlogFailurePolicy
	}{
		{name: "strict", value: "strict", expected: AuditlogFailurePolicyStrict},
		{name: "best effort", value: "bestEffort", expected: AuditlogFailurePolicyBestEffort},
	} {
		t.Run(test.name, func(t *testing.T) {
			var auditlog Auditlog
			require.NoError(t, yaml.Unmarshal([]byte("failurePolicy: "+test.value), &auditlog))
			require.Equal(t, test.expected, auditlog.FailurePolicy)
		})
	}

	for _, value := range []string{`""`, "best-effort", "besteffort", "Strict", "unknown"} {
		t.Run("reject "+value, func(t *testing.T) {
			var auditlog Auditlog
			err := yaml.Unmarshal([]byte("failurePolicy: "+value), &auditlog)
			require.ErrorContains(t, err, "illegal auditlog failure policy")
		})
	}
}

func TestAuditlogFailurePolicyYAMLRoundTrip(t *testing.T) {
	var auditlog Auditlog
	require.NoError(t, auditlog.SetDefaults())

	encoded, err := yaml.Marshal(auditlog)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "failurePolicy: strict\n")

	var decoded Auditlog
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))
	require.True(t, auditlog.IsEqualTo(decoded))

	decoded.FailurePolicy = AuditlogFailurePolicyBestEffort
	require.False(t, auditlog.IsEqualTo(decoded))
}
