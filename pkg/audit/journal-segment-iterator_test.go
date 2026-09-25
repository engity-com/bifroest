package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
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
	t.Cleanup(func() { require.NoError(t, inventory.segments.Close()) })
	runs, err := os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Len(t, runs, 1)
	info, err := runs[0].Info()
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}

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

func TestNativeSegmentRunPreservesModeAcrossSpill(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			directory, workspace := t.TempDir(), t.TempDir()
			for seq := journalSegmentSortChunkSize + 1; seq > 0; seq-- {
				name := nativeSegmentName(uint64(seq), journalHash{byte(seq), byte(seq >> 8)}, encrypted)
				require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0600))
			}
			inventory, err := newNativeSegmentInventory(context.Background(), directory, nativeActiveClear, encrypted, nil, func() (*journalSegmentWorkspace, error) {
				return newJournalSegmentWorkspace(workspace)
			})
			require.NoError(t, err)
			require.NotEmpty(t, inventory.segments.runPath)
			for expected := uint64(1); expected <= journalSegmentSortChunkSize+1; expected++ {
				segment, found, err := inventory.segments.Next(context.Background())
				require.NoError(t, err)
				require.True(t, found)
				require.Equal(t, nativeSegmentName(expected, segment.hash, encrypted), segment.name)
				require.Equal(t, filepath.Join(directory, segment.name), segment.path)
				require.Equal(t, expected, segment.sequence)
			}
			require.NoError(t, inventory.segments.Close())
			runs, err := os.ReadDir(workspace)
			require.NoError(t, err)
			require.Empty(t, runs)
		})
	}
}

func TestNativeSegmentInventoryCleansCanceledSpillAndPreservesUnknownFile(t *testing.T) {
	directory, workspace := t.TempDir(), t.TempDir()
	for seq := 1; seq <= journalSegmentSortChunkSize+1; seq++ {
		name := nativeSegmentName(uint64(seq), journalHash{byte(seq), byte(seq >> 8)}, false)
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0600))
	}
	ctx, cancel := context.WithCancel(context.Background())
	seen := 0
	_, err := newSortedJournalSegmentIteratorWithWorkspace(ctx, directory, func() (*journalSegmentWorkspace, error) {
		return newJournalSegmentWorkspace(workspace)
	}, func(entry os.DirEntry) (*journalSegmentFile, error) {
		seen++
		if seen > journalSegmentSortChunkSize {
			cancel()
		}
		seq, hash, ok := parseNativeSegmentName(entry.Name(), false)
		require.True(t, ok)
		return &journalSegmentFile{name: entry.Name(), sequence: seq, hash: hash}, nil
	})
	require.ErrorIs(t, err, context.Canceled)
	runs, err := os.ReadDir(workspace)
	require.NoError(t, err)
	require.Empty(t, runs)
	unknown := filepath.Join(directory, "unknown-user-file")
	require.NoError(t, os.WriteFile(unknown, []byte("keep"), 0600))
	_, err = newNativeSegmentInventory(context.Background(), directory, nativeActiveClear, false, nil, func() (*journalSegmentWorkspace, error) {
		return newJournalSegmentWorkspace(workspace)
	})
	require.Error(t, err)
	require.FileExists(t, unknown)
	runs, err = os.ReadDir(workspace)
	require.NoError(t, err)
	require.Empty(t, runs)
}

func TestNativeRecorderRecoveryDoesNotRequireGlobalTemp(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	unusableTemporaryDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unusableTemporaryDirectory, nil, 0600))
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, unusableTemporaryDirectory)
	}

	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())
	producer := producerJournalTestDirectory(conf, identity)
	entries, err := os.ReadDir(producer)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.FileExists(t, filepath.Join(producer, nativeHeadFileName))
	require.FileExists(t, filepath.Join(producer, nativeActiveClear))
	require.NoDirExists(t, filepath.Join(conf.Directory, journalWorkDirectoryName))
}
