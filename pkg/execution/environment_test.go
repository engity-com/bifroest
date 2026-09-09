package execution

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetEnvironmentRoundTrip(t *testing.T) {
	expected := map[string]string{
		"PATH":   "/target/bin:/usr/bin",
		"SECRET": "spaces, newlines\nand = signs",
	}

	encoded, err := EncodeTargetEnvironment(expected)
	require.NoError(t, err)
	actual, err := DecodeTargetEnvironment(encoded)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestDecodeTargetEnvironmentRejectsInvalidValue(t *testing.T) {
	_, err := DecodeTargetEnvironment("not-base64!")
	require.Error(t, err)
}
