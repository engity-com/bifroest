// SPDX-License-Identifier: Apache-2.0

package main

import (
	gos "os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestSignDarwinUsesHardenedRuntimeAndTimestamp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX executable")
	}
	directory := t.TempDir()
	logFilename := filepath.Join(directory, "codesign.log")
	codesignFilename := filepath.Join(directory, "codesign")
	require.NoError(t, gos.WriteFile(codesignFilename, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CODESIGN_LOG\"\n"), 0755))
	t.Setenv("PATH", directory+string(gos.PathListSeparator)+gos.Getenv("PATH"))
	t.Setenv("CODESIGN_LOG", logFilename)

	build, buildContext := testReleaseManifestBuild(t)
	build.binary.darwinSigningIdentity = "Developer ID Application: Engity GmbH (TEAMID)"
	artifact := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin, Arch: sys.ArchArm64, Edition: sys.EditionExtended}, buildArtifactTypeBinary, "bifroest", "binary", nil)

	require.NoError(t, build.binary.signDarwin(t.Context(), artifact))
	raw, err := gos.ReadFile(logFilename)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Equal(t, []string{
		"--force --sign Developer ID Application: Engity GmbH (TEAMID) --options runtime --timestamp " + artifact.filepath,
		"--verify --strict --verbose=2 " + artifact.filepath,
	}, lines)
}

func TestSignDarwinSkipsUnsignedAndNonDarwinArtifacts(t *testing.T) {
	build, buildContext := testReleaseManifestBuild(t)
	darwin := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin}, buildArtifactTypeBinary, "darwin", "binary", nil)
	require.NoError(t, build.binary.signDarwin(t.Context(), darwin))

	build.binary.darwinSigningIdentity = "identity"
	linux := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsLinux}, buildArtifactTypeBinary, "linux", "binary", nil)
	require.NoError(t, build.binary.signDarwin(t.Context(), linux))
}

func TestSignDarwinReportsCodesignFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX executable")
	}
	directory := t.TempDir()
	codesignFilename := filepath.Join(directory, "codesign")
	require.NoError(t, gos.WriteFile(codesignFilename, []byte("#!/bin/sh\necho rejected >&2\nexit 23\n"), 0755))
	t.Setenv("PATH", directory+string(gos.PathListSeparator)+gos.Getenv("PATH"))

	build, buildContext := testReleaseManifestBuild(t)
	build.binary.darwinSigningIdentity = "identity"
	artifact := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin}, buildArtifactTypeBinary, "darwin", "binary", nil)

	err := build.binary.signDarwin(t.Context(), artifact)
	require.ErrorContains(t, err, "codesign --force failed")
	require.ErrorContains(t, err, "rejected")
}
