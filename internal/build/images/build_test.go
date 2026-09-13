package images

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func TestApplyPlatformPreservesBaseWindowsVersion(t *testing.T) {
	configuration := &v1.ConfigFile{
		Architecture: "old",
		OS:           "old",
		OSVersion:    "10.0.20348.5622",
		OSFeatures:   []string{"win32k"},
		Variant:      "old-variant",
	}

	applyPlatform(configuration, &v1.Platform{Architecture: "amd64", OS: "windows"})

	require.Equal(t, "amd64", configuration.Architecture)
	require.Equal(t, "windows", configuration.OS)
	require.Equal(t, "10.0.20348.5622", configuration.OSVersion)
	require.Equal(t, []string{"win32k"}, configuration.OSFeatures)
	require.Equal(t, "old-variant", configuration.Variant)
}

func TestApplyPlatformUsesExplicitValues(t *testing.T) {
	configuration := &v1.ConfigFile{OSVersion: "old", OSFeatures: []string{"old"}, Variant: "old"}
	platform := &v1.Platform{
		Architecture: "arm",
		OS:           "linux",
		OSVersion:    "new",
		OSFeatures:   []string{"new"},
		Variant:      "v7",
	}

	applyPlatform(configuration, platform)

	require.Equal(t, platform.Architecture, configuration.Architecture)
	require.Equal(t, platform.OS, configuration.OS)
	require.Equal(t, platform.OSVersion, configuration.OSVersion)
	require.Equal(t, platform.OSFeatures, configuration.OSFeatures)
	require.Equal(t, platform.Variant, configuration.Variant)
}
