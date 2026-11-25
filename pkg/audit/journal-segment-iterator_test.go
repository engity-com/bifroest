package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func smallJournalSegmentSortOptions() journalSegmentSortOptions {
	return journalSegmentSortOptions{readBatchSize: 2, chunkSize: 3}
}

func TestJournalSegmentSortOptionsRetainProductionDefaults(t *testing.T) {
	want := journalSegmentSortOptions{readBatchSize: 128, chunkSize: 1_024}
	require.Equal(t, want, (journalSegmentSortOptions{}).defaults())
	require.Equal(t, want, (journalSegmentSortOptions{readBatchSize: -1, chunkSize: -1}).defaults())
	small := smallJournalSegmentSortOptions()
	require.Equal(t, small, small.defaults())
	require.Equal(t, want, (journalSegmentSortOptions{}).defaults(), "an override must not change another instance")
}

func TestJournalSegmentSorterSpillBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		options journalSegmentSortOptions
	}{
		{"small", smallJournalSegmentSortOptions()},
		{"production", journalSegmentSortOptions{}},
	} {
		for _, spill := range []bool{false, true} {
			name := test.name + map[bool]string{false: "/no-spill", true: "/spill"}[spill]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				directory := t.TempDir()
				sorter := &journalSegmentSorter{directory: directory, tempDirectory: directory, options: test.options}
				t.Cleanup(func() { require.NoError(t, sorter.cleanup()) })
				count := test.options.defaults().chunkSize
				if spill {
					count++
				}
				for sequence := count; sequence > 0; sequence-- {
					require.NoError(t, sorter.add(t.Context(), journalSegmentFile{sequence: uint64(sequence), hash: journalHash{byte(sequence)}}))
				}
				iterator, err := sorter.finish(t.Context())
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, iterator.Close()) })
				require.Equal(t, spill, iterator.runPath != "")
				if spill {
					info, err := iterator.run.Stat()
					require.NoError(t, err)
					require.EqualValues(t, count*journalSegmentRunRecordSize, info.Size())
				} else {
					require.Len(t, iterator.memory, count)
				}
				for pass := 0; pass < 2; pass++ {
					for expected := 1; expected <= count; expected++ {
						segment, found, err := iterator.Next(t.Context())
						require.NoError(t, err)
						require.True(t, found)
						require.EqualValues(t, expected, segment.sequence)
					}
					_, found, err := iterator.Next(t.Context())
					require.NoError(t, err)
					require.False(t, found)
					require.NoError(t, iterator.Reset())
				}
				require.NoError(t, iterator.Close())
				entries, err := os.ReadDir(directory)
				require.NoError(t, err)
				require.Empty(t, entries)
			})
		}
	}
}

func TestJournalSegmentInventoryCleansRunsOnClassificationError(t *testing.T) {
	directory, workspace := t.TempDir(), t.TempDir()
	options := smallJournalSegmentSortOptions()
	count := options.chunkSize + 2
	for sequence := 1; sequence <= count; sequence++ {
		name := sealedJournalFileName(uint64(sequence), journalHash{byte(sequence)})
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0600))
	}
	want := errors.New("classification failed after spill")
	seen, workspaces := 0, 0
	iterator, err := buildSortedJournalSegmentIterator(t.Context(), directory, "", func() (*journalSegmentWorkspace, error) {
		workspaces++
		return newJournalSegmentWorkspace(workspace)
	}, options, func(entry os.DirEntry) (*journalSegmentFile, error) {
		seen++
		if seen == count {
			return nil, want
		}
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		require.True(t, ok)
		return &journalSegmentFile{name: entry.Name(), sequence: sequence, hash: hash}, nil
	})
	require.ErrorIs(t, err, want)
	require.Nil(t, iterator)
	require.Equal(t, 1, workspaces)
	entries, err := os.ReadDir(workspace)
	require.NoError(t, err)
	require.Empty(t, entries)
	entries, err = os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, count)
}

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
	options := smallJournalSegmentSortOptions()
	count := 2*(options.chunkSize+1) + 1
	for sequence := 1; sequence <= count; sequence++ {
		hash := journalHash{byte(sequence), byte(sequence >> 8)}
		name := sealedJournalFileName(uint64(sequence), hash)
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0400))
	}
	ctx, cancel := context.WithCancel(context.Background())
	seen := 0
	_, err := buildSortedJournalSegmentIterator(ctx, directory, tempDirectory, nil, options, func(entry os.DirEntry) (*journalSegmentFile, error) {
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		require.True(t, ok)
		seen++
		if seen == count {
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
	options := smallJournalSegmentSortOptions()
	count := 3*(options.chunkSize+1) + 1
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			directory, workspace := t.TempDir(), t.TempDir()
			for seq := count; seq > 0; seq-- {
				name := nativeSegmentName(uint64(seq), journalHash{byte(seq), byte(seq >> 8)}, encrypted)
				require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0600))
			}
			inventory, err := newNativeSegmentInventoryWithOptions(context.Background(), directory, nativeActiveClear, encrypted, nil, func() (*journalSegmentWorkspace, error) {
				return newJournalSegmentWorkspace(workspace)
			}, options)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, inventory.segments.Close()) })
			require.NotEmpty(t, inventory.segments.runPath)
			for expected := uint64(1); expected <= uint64(count); expected++ {
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
	options := smallJournalSegmentSortOptions()
	count := 2*(options.chunkSize+1) + 1
	for seq := 1; seq <= count; seq++ {
		name := nativeSegmentName(uint64(seq), journalHash{byte(seq), byte(seq >> 8)}, false)
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), nil, 0600))
	}
	ctx, cancel := context.WithCancel(context.Background())
	seen := 0
	_, err := buildSortedJournalSegmentIterator(ctx, directory, "", func() (*journalSegmentWorkspace, error) {
		return newJournalSegmentWorkspace(workspace)
	}, options, func(entry os.DirEntry) (*journalSegmentFile, error) {
		seen++
		if seen == count {
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
	_, err = newNativeSegmentInventoryWithOptions(context.Background(), directory, nativeActiveClear, false, nil, func() (*journalSegmentWorkspace, error) {
		return newJournalSegmentWorkspace(workspace)
	}, options)
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
