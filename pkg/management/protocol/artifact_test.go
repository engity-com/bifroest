package protocol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArtifactRequestsAreFixedOriginalEvidenceSelectors(t *testing.T) {
	id := "00000001-0000-4000-8000-000000000001"
	for _, request := range []ArtifactRequest{{DownloadRecording, "default", id}, {DownloadAudit, "audit-1.2", ""}} {
		require.NoError(t, request.Validate())
	}
	for _, request := range []ArtifactRequest{{"command", "default", id}, {DownloadAudit, "default", id}, {DownloadRecording, "default", ""}, {DownloadRecording, "default", "00000000-0000-0000-0000-000000000000"}, {DownloadAudit, "../private", ""}, {DownloadAudit, "", ""}, {DownloadAudit, "credentials", "--includingCredentials"}} {
		require.Error(t, request.Validate())
	}
	for _, name := range []string{".", "..", "../x", "a_b", "a/b", "a\\b", "a:b", "a\x00b", "a\nb", "ü", strings.Repeat("a", 129)} {
		require.False(t, ValidAuditlogName(name), name)
	}
	require.True(t, ValidAuditlogName(strings.Repeat("a", 128)))
}
