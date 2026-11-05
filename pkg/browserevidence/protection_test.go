package browserevidence

import (
	"strings"
	"testing"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/stretchr/testify/require"
)

func TestBrowserEvidenceDiscoversSignedHeaderProtectionWithoutPromotingProducerTrust(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "vector", ID: recordingID}
	for _, encrypted := range []bool{false, true} {
		name, want := "bcast-v1.bcast", ""
		if encrypted {
			name, want = "becast-v1.becast", recipientPin
		}
		files := []File{{Name: "recording", Data: asset(t, "recording-format-vectors/native-v1", name)}}
		result, err := Verify(t.Context(), request, files, Options{Level: "outer", AllowUntrusted: true, RecipientFromHeader: true}, nil, nil)
		require.NoError(t, err)
		require.Equal(t, want, result.ExpectedRecipient)
		require.Equal(t, "untrusted", result.Trust)
		require.Empty(t, result.Output)
		result, err = Verify(t.Context(), request, files, Options{Level: "outer", Producer: strings.Repeat("1", 64), RecipientFromHeader: true}, nil, nil)
		require.ErrorIs(t, err, ErrVerification)
		require.Nil(t, result)
	}
}

func TestBrowserEvidenceDerivesRecipientLocallyFromPrivateKeyForRecordingsAndAudit(t *testing.T) {
	private := recipientPrivate(t, "tab secret")
	password := []byte("tab secret")
	for _, kind := range []string{"recording", "audit"} {
		request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "vector", ID: recordingID}
		files := []File{{Name: "recording", Data: asset(t, "recording-format-vectors/native-v1", "becast-v1.becast")}}
		options := Options{Level: "private", Export: true, AllowUntrusted: true, RecipientFromKey: true}
		if kind == "audit" {
			request.Operation = protocol.DownloadAudit
			request.ID = ""
			files = auditFiles(t, true)
			options.AuditScope = "complete"
		}
		result, err := Verify(t.Context(), request, files, options, private, password)
		require.NoError(t, err)
		require.Equal(t, recipientPin, result.ExpectedRecipient)
		require.Equal(t, "untrusted", result.Trust)
		require.Equal(t, "authenticated", result.Decryption)
		require.NotEmpty(t, result.Output)
		result, err = Verify(t.Context(), request, files, options, private, []byte("wrong secret"))
		require.ErrorIs(t, err, ErrKey)
		require.Nil(t, result)
		require.NotContains(t, err.Error(), "secret")
		options.Producer = strings.Repeat("1", 64)
		result, err = Verify(t.Context(), request, files, options, private, password)
		require.ErrorIs(t, err, ErrVerification)
		require.Nil(t, result)
	}
}
