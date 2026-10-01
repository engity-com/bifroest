//go:build darwin

package main

import (
	"io"
	gos "os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

func TestOpenDarwinServiceBinaryRejectsInvalidSources(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "executable")
	require.NoError(t, gos.WriteFile(executable, []byte("trusted"), 0755))
	nonExecutable := filepath.Join(directory, "non-executable")
	require.NoError(t, gos.WriteFile(nonExecutable, []byte("trusted"), 0644))
	symlink := filepath.Join(directory, "symlink")
	require.NoError(t, gos.Symlink(executable, symlink))
	fifo := filepath.Join(directory, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0755))

	for name, source := range map[string]string{
		"directory":      directory,
		"fifo":           fifo,
		"non-executable": nonExecutable,
		"symlink":        symlink,
	} {
		t.Run(name, func(t *testing.T) {
			file, err := openDarwinServiceBinary(source)
			require.Error(t, err)
			require.Nil(t, file)
		})
	}
}

func TestOpenDarwinServiceBinaryPinsSource(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "bifroest")
	require.NoError(t, gos.WriteFile(source, []byte("trusted"), 0755))

	file, err := openDarwinServiceBinary(source)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	require.NoError(t, gos.Rename(source, source+".original"))
	require.NoError(t, gos.WriteFile(source, []byte("replacement"), 0755))
	contents, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Equal(t, "trusted", string(contents))
	replacement, err := gos.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, "replacement", string(replacement))
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
