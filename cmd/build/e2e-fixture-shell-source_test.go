package main

import (
	gos "os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2EFixtureShellSourceDownloadFailsClosed(t *testing.T) {
	raw, err := gos.ReadFile("../../test/e2e/docker_backend_test.go")
	require.NoError(t, err)
	_, rest, found := strings.Cut(string(raw), "WORKDIR /src\nRUN ")
	require.True(t, found)
	download, _, found := strings.Cut(rest, "\nCOPY read-key-cursor.patch")
	require.True(t, found)

	sh, err := osexec.LookPath("sh")
	if err != nil {
		t.Skip("a POSIX shell is required to exercise the fixture Containerfile's download step")
	}
	for _, tt := range []struct {
		name, primary, mirror, checksum, calls string
		exit                                   int
	}{
		{"primary", "0", "99", "0", "primary\nchecksum\ntar\n", 0},
		{"network-fallback", "28", "0", "0", "primary\nmirror\nchecksum\ntar\n", 0},
		{"http-fallback", "22", "0", "0", "primary\nmirror\nchecksum\ntar\n", 0},
		{"both-unavailable", "28", "28", "0", "primary\nmirror\n", 28},
		{"primary-checksum-mismatch", "0", "0", "1", "primary\nchecksum\n", 1},
		{"mirror-checksum-mismatch", "28", "0", "1", "primary\nmirror\nchecksum\n", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Stub the tools, but execute the exact RUN body with its real set -e
			// control flow. The stubs also check TLS, URLs, digest and tar ordering.
			script := `curl() {
  case "$*" in
    "--fail --location --proto =https --proto-redir =https --tlsv1.2 --connect-timeout 10 https://busybox.net/downloads/busybox-1.37.0.tar.bz2 -o /busybox-1.37.0.tar.bz2")
      printf 'primary\n' >> calls
      return "$PRIMARY_STATUS"
      ;;
    "--fail --location --proto =https --proto-redir =https --tlsv1.2 --connect-timeout 10 https://sources.buildroot.net/busybox/busybox-1.37.0.tar.bz2 -o /busybox-1.37.0.tar.bz2")
      printf 'mirror\n' >> calls
      return "$MIRROR_STATUS"
      ;;
    *) return 91 ;;
  esac
}
sha256sum() {
  [ "$*" = '-c -' ] || return 92
  IFS= read -r digest || return 93
  [ "$digest" = '3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4  /busybox-1.37.0.tar.bz2' ] || return 94
  printf 'checksum\n' >> calls
  [ "$CHECKSUM_STATUS" = 0 ] || return "$CHECKSUM_STATUS"
  printf verified > verified
}
tar() {
  [ "$*" = '-xjf /busybox-1.37.0.tar.bz2' ] || return 95
  [ -f verified ] || return 96
  printf 'tar\n' >> calls
}
` + "PRIMARY_STATUS=" + tt.primary + "\nMIRROR_STATUS=" + tt.mirror + "\nCHECKSUM_STATUS=" + tt.checksum + "\n" + download
			directory := t.TempDir()
			scriptPath := filepath.Join(directory, "fixture-shell-source.sh")
			// Use a file so Windows command-line quoting cannot alter shell escapes.
			require.NoError(t, gos.WriteFile(scriptPath, []byte(script), 0o600))
			command := osexec.CommandContext(t.Context(), sh, filepath.ToSlash(scriptPath))
			command.Dir = directory
			output, runErr := command.CombinedOutput()
			if tt.exit == 0 {
				require.NoError(t, runErr, string(output))
			} else {
				var exited *osexec.ExitError
				require.ErrorAs(t, runErr, &exited, string(output))
				require.Equal(t, tt.exit, exited.ExitCode(), string(output))
			}
			calls, err := gos.ReadFile(filepath.Join(directory, "calls"))
			require.NoError(t, err)
			require.Equal(t, tt.calls, strings.ReplaceAll(string(calls), "\r\n", "\n"))
		})
	}
}
