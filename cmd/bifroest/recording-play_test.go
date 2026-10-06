package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/engity-com/bifroest/pkg/management"
	"github.com/stretchr/testify/require"
)

func TestRecordingPlaybackRequiresSensitiveAndDecryptsLocally(t *testing.T) {
	fixture := newRecordingExportTestFixture(t)
	for _, test := range []struct {
		path       string
		identities []string
	}{
		{fixture.nativeClearPath, nil},
		{fixture.nativeEncryptedPath, []string{fixture.identityPath}},
	} {
		opts := recordingPlayOpts{recordingExportOpts: recordingExportOpts{
			file: test.path, expectedProducerId: fixture.identity.ProducerId().String(),
			decryptionIdentityFiles: test.identities,
		}, speed: 100}
		var output bytes.Buffer
		require.ErrorContains(t, doRecordingPlay(t.Context(), &opts, &output), "--with-sensitive")
		require.Empty(t, output.String())
		opts.withSensitive = true
		require.NoError(t, doRecordingPlay(t.Context(), &opts, &output))
		require.Contains(t, output.String(), "sensitive terminal output")
		require.NotContains(t, output.String(), "bifroest:metadata")
	}
}

func TestPlaybackParserRejectsInvalidHeader(t *testing.T) {
	require.ErrorContains(t, management.PlayAsciicast(t.Context(), strings.NewReader("{}\n"), &bytes.Buffer{}, 1), "unsupported asciicast")
}
