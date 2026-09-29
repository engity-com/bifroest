//go:build darwin

package main

import (
	gos "os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinServicePlist(t *testing.T) {
	configuration := "/Library/Application Support/Engity/Bifroest/configuration & test.yaml"
	contents := darwinServicePlistContents(configuration)
	require.Contains(t, string(contents), "--configuration=/Library/Application Support/Engity/Bifroest/configuration &amp; test.yaml")
	require.Contains(t, string(contents), "<string>"+darwinServiceBinary+"</string>")
	require.Contains(t, string(contents), "<string>"+darwinServiceLabel+"</string>")

	filename := filepath.Join(t.TempDir(), "service.plist")
	require.NoError(t, gos.WriteFile(filename, contents, 0600))
	output, err := exec.Command("plutil", "-lint", filename).CombinedOutput()
	require.NoError(t, err, string(output))
}

func TestDarwinServicePlistDoesNotUseShell(t *testing.T) {
	contents := string(darwinServicePlistContents(defaultConfigurationRef))
	for _, forbidden := range []string{"/bin/sh", "/bin/bash", "python"} {
		require.NotContains(t, strings.ToLower(contents), forbidden)
	}
}

func TestDarwinServiceRejectsConfigurationOutsideManagedState(t *testing.T) {
	err := validateDarwinServiceConfiguration(filepath.Join(t.TempDir(), "configuration.yaml"))
	require.ErrorContains(t, err, "configuration must be located below "+darwinServiceStateDirectory)
}

func TestDarwinServiceCommandsUseFixedEnvironment(t *testing.T) {
	t.Setenv("PATH", "/tmp/untrusted")
	require.Equal(t, []string{
		"HOME=/var/root",
		"PATH=" + darwinServiceExecutablePath,
	}, darwinServiceCommandEnvironment())
}
