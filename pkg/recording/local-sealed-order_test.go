package recording

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/uuidtext"
)

func sealedOrderFixture(t *testing.T) (*LocalNativeRecordingRepository, string, []Id) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	root := t.TempDir()
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	var ids []Id
	for _, text := range []string{"04c52d2e-e139-49a2-a399-21ddd65a3502", "34e34ab8-7457-4d88-a5e4-c57791775c3a"} {
		var id Id
		require.NoError(t, id.UnmarshalText([]byte(text)))
		ids = append(ids, id)
	}
	require.Greater(t, ids[0].String(), ids[1].String(), "fixture must distinguish UUID bytes from Base58 text order")
	for index := len(ids) - 1; index >= 0; index-- {
		current := metadata
		current.RecordingId = ids[index]
		active, err := repo.CreateActive(t.Context(), header, current, 300)
		require.NoError(t, err)
		_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: current.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
	}
	return repo, root, ids
}

func TestLocalSealedListsAgreeOnUUIDByteOrderAcrossNotations(t *testing.T) {
	for _, classic := range []bool{false, true} {
		t.Run(map[bool]string{false: "base58", true: "mixed-classic"}[classic], func(t *testing.T) {
			repo, root, ids := sealedOrderFixture(t)
			if classic {
				require.NoError(t, os.Rename(filepath.Join(root, "sealed", ids[1].String()+".bcast"), filepath.Join(root, "sealed", uuidtext.Classic(ids[1])+".bcast")))
			}
			all, err := repo.ListSealed(t.Context())
			require.NoError(t, err)
			require.Equal(t, ids, all)
			for index := range ids {
				options := SealedPageOptions{Limit: 1}
				if index > 0 {
					options.After = ids[index-1]
				}
				page, err := repo.ListSealedPage(t.Context(), options)
				require.NoError(t, err)
				require.Equal(t, ids[index:index+1], page)
			}
		})
	}
}

func TestLocalSealedFullListRejectsDuplicateIdentityEvenForHardlinks(t *testing.T) {
	repo, root, ids := sealedOrderFixture(t)
	require.NoError(t, os.Link(filepath.Join(root, "sealed", ids[0].String()+".bcast"), filepath.Join(root, "sealed", uuidtext.Classic(ids[0])+".bcast")))
	_, err := repo.ListSealed(t.Context())
	require.ErrorContains(t, err, "ambiguous sealed artifacts")
	_, err = repo.ListSealedPage(t.Context(), SealedPageOptions{Limit: 1})
	require.ErrorContains(t, err, "ambiguous sealed artifacts")
}
