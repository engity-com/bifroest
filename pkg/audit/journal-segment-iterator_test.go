package audit

import (
	"context"
	goerrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestJournalSegmentInventorySortsWithBoundedTemporaryRuns(t *testing.T) {
	directory := t.TempDir()
	tempDirectory := t.TempDir()
	const count = journalSegmentSortChunkSize + 17
	for sequence := count; sequence >= 1; sequence-- {
		hash := journalHash{byte(sequence), byte(sequence >> 8)}
		name := sealedJournalFileName(uint64(sequence), hash)
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0400))
	}

	inventory, err := newJournalSegmentInventory(context.Background(), directory, tempDirectory)
	require.NoError(t, err)
	runs, err := os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Len(t, runs, 1)
	info, err := runs[0].Info()
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	for expected := uint64(1); expected <= uint64(count); expected++ {
		segment, found, err := inventory.segments.Next(context.Background())
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, expected, segment.sequence)
	}
	_, found, err := inventory.segments.Next(context.Background())
	require.NoError(t, err)
	require.False(t, found)
	require.NoError(t, inventory.segments.Close())
	runs, err = os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Empty(t, runs)
}

func TestJournalSegmentInventoryCleansRunsOnCancellation(t *testing.T) {
	directory := t.TempDir()
	tempDirectory := t.TempDir()
	for sequence := 1; sequence <= journalSegmentSortChunkSize+1; sequence++ {
		hash := journalHash{byte(sequence), byte(sequence >> 8)}
		name := sealedJournalFileName(uint64(sequence), hash)
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0400))
	}
	ctx, cancel := context.WithCancel(context.Background())
	seen := 0
	_, err := newSortedJournalSegmentIterator(ctx, directory, tempDirectory, func(entry os.DirEntry) (*journalSegmentFile, error) {
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		require.True(t, ok)
		seen++
		if seen > journalSegmentSortChunkSize {
			cancel()
		}
		return &journalSegmentFile{name: entry.Name(), sequence: sequence, hash: hash}, nil
	})
	require.ErrorIs(t, err, context.Canceled)
	runs, readErr := os.ReadDir(tempDirectory)
	require.NoError(t, readErr)
	require.Empty(t, runs)
}

func TestJournalSegmentSorterResumesCanceledRunMerge(t *testing.T) {
	tempDirectory := t.TempDir()
	left := journalSegmentFile{sequence: 1, hash: journalHash{1}}
	right := journalSegmentFile{sequence: 2, hash: journalHash{2}}
	leftPath, err := writeJournalSegmentRun(context.Background(), tempDirectory, []journalSegmentFile{left})
	require.NoError(t, err)
	rightPath, err := writeJournalSegmentRun(context.Background(), tempDirectory, []journalSegmentFile{right})
	require.NoError(t, err)
	sorter := &journalSegmentSorter{
		directory:     tempDirectory,
		tempDirectory: tempDirectory,
		runs:          []string{leftPath},
		pendingRun:    rightPath,
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, sorter.resume(canceled), context.Canceled)
	require.FileExists(t, leftPath)
	require.FileExists(t, rightPath)

	iterator, err := sorter.finish(context.Background())
	require.NoError(t, err)
	for expected := uint64(1); expected <= 2; expected++ {
		segment, found, err := iterator.Next(context.Background())
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, expected, segment.sequence)
	}
	_, found, err := iterator.Next(context.Background())
	require.NoError(t, err)
	require.False(t, found)
	require.NoError(t, iterator.Close())
	runs, err := os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Empty(t, runs)
}

func TestJournalSegmentSorterResumesCanceledFinalMerge(t *testing.T) {
	tempDirectory := t.TempDir()
	firstPath, err := writeJournalSegmentRun(context.Background(), tempDirectory, []journalSegmentFile{{sequence: 2, hash: journalHash{2}}})
	require.NoError(t, err)
	secondPath, err := writeJournalSegmentRun(context.Background(), tempDirectory, []journalSegmentFile{{sequence: 1, hash: journalHash{1}}})
	require.NoError(t, err)
	sorter := &journalSegmentSorter{
		directory:     tempDirectory,
		tempDirectory: tempDirectory,
		runs:          []string{firstPath, secondPath},
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sorter.finish(canceled)
	require.ErrorIs(t, err, context.Canceled)
	require.FileExists(t, firstPath)
	require.FileExists(t, secondPath)

	iterator, err := sorter.finish(context.Background())
	require.NoError(t, err)
	for expected := uint64(1); expected <= 2; expected++ {
		segment, found, err := iterator.Next(context.Background())
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, expected, segment.sequence)
	}
	require.NoError(t, iterator.Close())
	runs, err := os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Empty(t, runs)
}

func TestRecorderRecoveryUsesJournalWorkspaceWithoutGlobalTemp(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	unusableTemporaryDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unusableTemporaryDirectory, nil, 0600))
	t.Setenv("TMPDIR", unusableTemporaryDirectory)

	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())
	workRoot := filepath.Join(conf.Journal.Directory, journalWorkDirectoryName)
	entries, err := os.ReadDir(workRoot)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func inventoryJournalTestSegments(directory string) ([]journalSegmentFile, bool, error) {
	workspace, err := bfcrypto.CreateProtectedTempDirectory(os.TempDir(), ".bifroest-audit-test-*")
	if err != nil {
		return nil, false, err
	}
	inventory, err := newJournalSegmentInventory(context.Background(), directory, workspace)
	if err != nil {
		return nil, false, goerrors.Join(err, os.Remove(workspace))
	}
	var segments []journalSegmentFile
	for {
		segment, found, err := inventory.segments.Next(context.Background())
		if err != nil {
			return nil, false, goerrors.Join(err, inventory.segments.Close(), os.Remove(workspace))
		}
		if !found {
			break
		}
		segments = append(segments, segment)
	}
	return segments, inventory.hasActive, goerrors.Join(inventory.segments.Close(), os.Remove(workspace))
}
