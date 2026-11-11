package recording

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/stretchr/testify/require"
)

func TestBase58RepositoryReadsHistoricalUUIDFilenamesWithoutRewritingEvidence(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, true)
			root := filepath.Join(t.TempDir(), "recordings")
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.NoError(t, repo.Close())
			suffix := ".bcast"
			fixture := "bcast-v1.bcast"
			if encrypted {
				suffix = ".becast"
				fixture = "becast-v1.becast"
			}
			original := nativeRecordingVector(t, fixture)
			legacyName := uuidtext.Classic(metadata.RecordingId) + suffix
			legacyPath := filepath.Join(root, "sealed", legacyName)
			require.NoError(t, os.WriteFile(legacyPath, original, 0600))
			repo, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			ids, err := repo.ListSealed(t.Context())
			resolved, exists, nameErr := repo.ArtifactFileName(metadata.RecordingId)
			require.NoError(t, nameErr)
			require.True(t, exists)
			require.Equal(t, legacyName, resolved)
			require.NoError(t, err)
			require.Equal(t, []Id{metadata.RecordingId}, ids)
			artifact, err := repo.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err)
			require.Equal(t, legacyName, artifact.FileName())
			require.NoError(t, artifact.Close())
			var summaries []NativeRecordingSummary
			require.NoError(t, repo.WalkCatalog(t.Context(), func(row NativeRecordingSummary) error { summaries = append(summaries, row); return nil }, nil))
			require.Len(t, summaries, 1)
			require.Equal(t, metadata.RecordingId, summaries[0].RecordingId)
			_, err = repo.CreateActive(t.Context(), header, metadata, 0)
			require.Error(t, err, "a legacy alias must prevent duplicate creation")
			data, err := os.ReadFile(legacyPath)
			require.NoError(t, err)
			require.True(t, bytes.Equal(original, data))
			currentPath := filepath.Join(root, "sealed", metadata.RecordingId.String()+suffix)
			require.NoFileExists(t, currentPath)
			require.NoError(t, os.WriteFile(currentPath, original, 0600))
			_, err = repo.OpenSealed(t.Context(), metadata.RecordingId)
			require.ErrorContains(t, err, "ambiguous")
			require.NoError(t, repo.Close())
			_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.ErrorContains(t, err, "ambiguous")
			for _, path := range []string{legacyPath, currentPath} {
				data, err = os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, original, data)
			}
		})
	}
}
