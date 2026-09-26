package main

import (
	"bytes"
	"crypto/ed25519"
	goos "os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingVerifyOfflineScopesAndTrust(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	opts := recordingVerifyOpts{file: fixture.nativeClearPath, expectedProducerId: fixture.identity.ProducerId().String()}
	var output bytes.Buffer
	require.NoError(t, doRecordingVerify(&opts, &output))
	require.Equal(t, "verified (scope: full)\n", output.String())
	opts.file = fixture.nativeEncryptedPath
	output.Reset()
	require.NoError(t, doRecordingVerify(&opts, &output))
	require.Equal(t, "verified (scope: outer)\n", output.String())
	opts.requireFull = true
	output.Reset()
	require.ErrorContains(t, doRecordingVerify(&opts, &output), "requires --decryptionIdentityFile")
	require.Empty(t, output.String())
	opts.decryptionIdentityFiles = []string{fixture.identityPath}
	require.NoError(t, doRecordingVerify(&opts, &output))
	require.Equal(t, "verified (scope: full)\n", output.String())
	opts.expectedProducerId = strings.Repeat("a", 64)
	output.Reset()
	require.Error(t, doRecordingVerify(&opts, &output))
	require.Empty(t, output.String())
	opts.expectedProducerId = ""
	require.ErrorContains(t, doRecordingVerify(&opts, &output), "--expectedProducerId is required")
	opts.expectedProducerId = fixture.identity.ProducerId().String()
	opts.decryptionIdentityFiles = []string{writeRecordingExportTestPrivateKey(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)))}
	require.ErrorContains(t, doRecordingVerify(&opts, &output), "cannot fully verify")
	require.Empty(t, output.String())
}

func TestRecordingVerifyLocalSelectionAndAmbiguousFormat(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	root := t.TempDir()
	sealed := filepath.Join(root, "recordings", "sealed")
	require.NoError(t, goos.MkdirAll(sealed, 0700))
	name := fixture.recordingId.String() + ".bcast"
	content, err := goos.ReadFile(fixture.nativeClearPath)
	require.NoError(t, err)
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, name), content, 0600))
	configPath := filepath.Join(root, "configuration.yaml")
	raw := "auditlog:\n  - enabled: false\n    identityFile: " + fixture.signingIdentityPath + "\n    recording:\n      enabled: true\n      directory: " + filepath.Join(root, "recordings") + "\nflows:\n  - name: flow\n    authorization:\n      type: simple\n    environment:\n      type: dummy\n"
	require.NoError(t, goos.WriteFile(configPath, []byte(raw), 0600))
	opts := recordingVerifyOpts{file: "default", recordingId: fixture.recordingId.String(), configuration: configPath, requireFull: true}
	var output bytes.Buffer
	require.NoError(t, doRecordingVerify(&opts, &output))
	require.Equal(t, "verified (scope: full)\n", output.String())
	otherId := "11111111-1111-4111-8111-111111111111"
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, otherId+".bcast"), content, 0600))
	output.Reset()
	misnamed := opts
	misnamed.recordingId = otherId
	require.ErrorContains(t, doRecordingVerify(&misnamed, &output), "canonical sealed Recording file name")
	require.Empty(t, output.String())
	cast, err := goos.ReadFile(fixture.castPath)
	require.NoError(t, err)
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, otherId+".bcast"), cast, 0600))
	require.ErrorContains(t, doRecordingVerify(&misnamed, &output), "native sealed Recording artifact")
	require.Empty(t, output.String())
	require.ErrorContains(t, doRecordingVerify(&recordingVerifyOpts{file: filepath.Join(sealed, name)}, &bytes.Buffer{}), "--expectedProducerId is required")
	require.ErrorContains(t, doRecordingVerify(&recordingVerifyOpts{file: "default", recordingId: "../../etc/passwd", configuration: configPath}, &bytes.Buffer{}), "illegal recording ID")
	require.NoError(t, goos.WriteFile(filepath.Join(sealed, fixture.recordingId.String()+".becast"), content, 0600))
	require.ErrorContains(t, doRecordingVerify(&opts, &bytes.Buffer{}), "both clear and encrypted")
}
