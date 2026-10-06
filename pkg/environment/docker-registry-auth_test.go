package environment

import (
	"encoding/base64"
	"testing"

	"github.com/moby/moby/api/types/registry"
	"github.com/stretchr/testify/require"
)

func TestDockerAuthConfigEncoding(t *testing.T) {
	config := registry.AuthConfig{Username: "user", Password: "p@ss", ServerAddress: "registry.example.org"}
	encoded, err := encodeDockerAuthConfig(config)
	require.NoError(t, err)
	_, err = base64.URLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	decoded, err := decodeDockerAuthConfig(encoded)
	require.NoError(t, err)
	require.Equal(t, config, *decoded)
}
