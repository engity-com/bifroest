// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
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

func TestBuildRemovesDarwinSecretsFromProcessEnvironment(t *testing.T) {
	for _, name := range darwinSecretEnvironment {
		t.Setenv(name, "secret")
	}

	build, _ := testReleaseManifestBuild(t)
	build.binary.clearDarwinSecretsFromEnvironment()

	for _, name := range darwinSecretEnvironment {
		require.Empty(t, gos.Getenv(name))
	}
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

func TestPrepareDarwinReleaseOwnsCredentialLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses POSIX executables")
	}
	directory := t.TempDir()
	logFilename := filepath.Join(directory, "commands.log")
	t.Setenv("DARWIN_COMMAND_LOG", logFilename)
	t.Setenv("PATH", directory+string(gos.PathListSeparator)+gos.Getenv("PATH"))
	t.Setenv(darwinCertificateEnvironment, "must-not-reach-child-processes")
	t.Setenv(darwinCertificatePasswordEnvironment, "must-not-reach-child-processes")
	t.Setenv(darwinNotaryKeyEnvironment, "must-not-reach-child-processes")
	writeDarwinTestCommand(t, directory, "lipo", "test -z \"${BIFROEST_DARWIN_CERTIFICATE:-}${BIFROEST_DARWIN_CERTIFICATE_PASSWORD:-}${BIFROEST_DARWIN_NOTARY_KEY:-}\"; echo arm64")
	writeDarwinTestCommand(t, directory, "file", "echo 'Mach-O 64-bit executable arm64'")
	writeDarwinTestCommand(t, directory, "vtool", "echo 'minos 13.0'")
	writeDarwinTestCommand(t, directory, "otool", "printf '%s\\n' binary '/usr/lib/libpam.2.dylib (compatibility version 1.0.0)' '/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)'")
	writeDarwinTestCommand(t, directory, "nm", "printf '%s\\n' '(undefined) external _pam_start (from libpam)' '(undefined) external _pam_authenticate (from libpam)' '(undefined) external _pam_acct_mgmt (from libpam)'")
	writeDarwinTestCommand(t, directory, "strings", ":")
	writeDarwinTestCommand(t, directory, "security", "if test \"$*\" = 'list-keychains -d user'; then echo '\"/Users/test/Login Keychain.keychain-db\"'; elif test \"$1\" = find-identity; then echo 'Developer ID Application: Engity GmbH (TEAMID)'; fi")
	writeDarwinTestCommand(t, directory, "codesign", "if test \"$1\" = --display; then printf '%s\\n' 'Authority=Developer ID Application: Engity GmbH (TEAMID)' 'TeamIdentifier=TEAMID' 'CodeDirectory v=20500 size=1 flags=0x10000(runtime)' 'Timestamp=Sep 28, 2026'; fi")
	writeDarwinTestCommand(t, directory, "ditto", ":")
	writeDarwinTestCommand(t, directory, "xcrun", "echo '{\"id\":\"submission\",\"status\":\"Accepted\"}'")
	writeDarwinTestCommand(t, directory, "spctl", "if test \"$1\" = --status; then echo 'assessments enabled'; else echo 'source=Notarized Developer ID'; fi")

	build, buildContext := testReleaseManifestBuild(t)
	build.binary.darwinSigningIdentity = "Developer ID Application: Engity GmbH (TEAMID)"
	build.binary.darwinCertificate = base64.StdEncoding.EncodeToString([]byte("certificate"))
	build.binary.darwinCertificatePass = "certificate-password"
	build.binary.darwinNotaryKey = "notary-key"
	build.binary.darwinNotaryKeyId = "KEYID"
	build.binary.darwinNotaryIssuer = "ISSUER"
	build.binary.darwinReleaseRequired = true
	artifact := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin, Arch: sys.ArchArm64, Edition: sys.EditionExtended}, buildArtifactTypeBinary, "bifroest", "#!/bin/sh\necho version\n", nil)
	require.NoError(t, gos.Chmod(artifact.filepath, 0755))

	require.NoError(t, build.binary.prepareDarwinBinary(t.Context(), artifact))
	raw, err := gos.ReadFile(logFilename)
	require.NoError(t, err)
	commands := string(raw)
	require.Contains(t, commands, "security create-keychain")
	require.Contains(t, commands, "codesign --force --sign Developer ID Application: Engity GmbH (TEAMID) --options runtime --timestamp")
	require.Contains(t, commands, "xcrun notarytool submit")
	require.Contains(t, commands, "--output-format json")
	require.Contains(t, commands, "spctl --assess --type execute")
	require.Contains(t, commands, "security list-keychains -d user -s /Users/test/Login Keychain.keychain-db")
	require.Contains(t, commands, "security delete-keychain")
}

func TestNotarizeDarwinRejectsInvalidSubmission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses POSIX executables")
	}
	directory := t.TempDir()
	t.Setenv("DARWIN_COMMAND_LOG", filepath.Join(directory, "commands.log"))
	t.Setenv("PATH", directory+string(gos.PathListSeparator)+gos.Getenv("PATH"))
	writeDarwinTestCommand(t, directory, "ditto", ":")
	writeDarwinTestCommand(t, directory, "xcrun", "echo '{\"id\":\"submission\",\"status\":\"Invalid\"}'")

	build, buildContext := testReleaseManifestBuild(t)
	build.binary.darwinNotaryKey = "notary-key"
	build.binary.darwinNotaryKeyId = "KEYID"
	build.binary.darwinNotaryIssuer = "ISSUER"
	artifact := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin}, buildArtifactTypeBinary, "bifroest", "binary", nil)

	err := build.binary.notarizeDarwin(t.Context(), artifact, directory)
	require.ErrorContains(t, err, `notarization "submission" finished with status "Invalid"`)
}

func TestParseDarwinKeychainSearchList(t *testing.T) {
	actual, err := parseDarwinKeychainSearchList("  \"/Users/test/Library/Keychains/login.keychain-db\"\n\"/Users/test/Library/Keychains/with space.keychain-db\"\n")
	require.NoError(t, err)
	require.Equal(t, []string{
		"/Users/test/Library/Keychains/login.keychain-db",
		"/Users/test/Library/Keychains/with space.keychain-db",
	}, actual)
}

func TestPrepareDarwinReleaseRejectsIncompleteCredentials(t *testing.T) {
	build, buildContext := testReleaseManifestBuild(t)
	artifact := testReleaseManifestFile(t, buildContext, &bib.Platform{Os: sys.OsDarwin}, buildArtifactTypeBinary, "bifroest", "binary", nil)
	build.binary.darwinCertificate = "certificate"
	require.ErrorContains(t, build.binary.prepareDarwinBinary(t.Context(), artifact), "must be configured together")

	build.binary.darwinCertificate = ""
	build.binary.darwinNotaryKey = "notary-key"
	build.binary.darwinNotaryKeyId = "KEYID"
	build.binary.darwinNotaryIssuer = "ISSUER"
	require.ErrorContains(t, build.binary.prepareDarwinBinary(t.Context(), artifact), "notarization requires a signing identity")

	build.binary.darwinNotaryKey = ""
	build.binary.darwinNotaryKeyId = ""
	build.binary.darwinNotaryIssuer = ""
	build.binary.darwinReleaseRequired = true
	require.ErrorContains(t, build.binary.prepareDarwinBinary(t.Context(), artifact), "require a signing certificate")
}

func writeDarwinTestCommand(t *testing.T, directory, name, body string) {
	t.Helper()
	script := "#!/bin/sh\nset -e\nprintf '%s\\n' \"" + name + " $*\" >> \"$DARWIN_COMMAND_LOG\"\n" + body + "\n"
	require.NoError(t, gos.WriteFile(filepath.Join(directory, name), []byte(script), 0755))
}
