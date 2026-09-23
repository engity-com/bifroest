//go:build unix

package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyJournalsDoesNotRecoverInterruptedHardLinkPublication(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-publish-crash"}))
	sealed := appendSealAndCrashCloseJournalTestRecorder(t, recorder)

	activePath := journalTestActivePath(conf, identity)
	require.NoError(t, os.Chmod(activePath, 0400))
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	targetPath := filepath.Join(producerJournalTestDirectory(conf, identity), nativeSegmentName(sealed.seq, hashNativeAuditSegment(raw), false))
	require.NoError(t, os.Link(activePath, targetPath))
	before := snapshotJournalTestTree(t, conf.Journal.Directory)

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "default", Directory: conf.Journal.Directory}})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 1)
	require.Equal(t, before, snapshotJournalTestTree(t, conf.Journal.Directory))
	require.FileExists(t, activePath)
	require.FileExists(t, targetPath)
}
