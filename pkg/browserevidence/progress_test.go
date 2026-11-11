package browserevidence

import (
	"errors"
	"testing"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/stretchr/testify/require"
)

func TestBrowserAuditProgressNeverChangesTrustOrReleasesPartialVerification(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "vector"}
	for _, encrypted := range []bool{false, true} {
		files := auditFiles(t, encrypted)
		recipient := ""
		var private []byte
		if encrypted {
			recipient = recipientPin
			private = recipientPrivate(t, "")
		}
		var phases []string
		options := Options{Producer: producerPin, Recipient: recipient, Level: "private", Export: true, AuditScope: "complete", Progress: func(phase string, completed, total int64) error {
			phases = append(phases, phase)
			require.GreaterOrEqual(t, completed, int64(0))
			require.GreaterOrEqual(t, total, int64(-1))
			return nil
		}}
		result, err := Verify(t.Context(), request, files, options, private, nil)
		require.NoError(t, err)
		require.Equal(t, "pinned", result.Trust)
		require.NotEmpty(t, result.Output)
		require.Contains(t, phases, "integrity")
		require.Contains(t, phases, "decrypting")
		require.Contains(t, phases, "exporting")
		for _, stop := range []string{"integrity", "decrypting", "exporting"} {
			canceled := errors.New("progress consumer canceled")
			options.Progress = func(phase string, _, _ int64) error {
				if phase == stop {
					return canceled
				}
				return nil
			}
			result, err = Verify(t.Context(), request, files, options, private, nil)
			require.Error(t, err)
			require.Nil(t, result, "progress is not a successful verification receipt or authority to return partial output")
		}
	}
}
