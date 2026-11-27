package configuration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fileWatchTestStart(t *testing.T, reloader *FileReloader, options FileWatchOptions) (<-chan error, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done, failures := make(chan error, 1), make(chan error, 16)
	ready := make(chan struct{})
	markReady := sync.OnceFunc(func() { close(ready) })
	options.OnError = func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	options.OnReload = func(ReloadChanges) { markReady() }
	go func() { done <- reloader.Watch(ctx, options) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Error("configuration watcher did not stop")
		}
	})
	select {
	case <-ready:
	case err := <-failures:
		t.Fatalf("initial configuration watch failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("configuration watcher did not accept its initial file")
	}
	return done, failures
}

func fileWatchTestAwaitBanner(t *testing.T, reloader *FileReloader, expected string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return reloader.Current().Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String() == expected
	}, 3*time.Second, 5*time.Millisecond)
}

func TestFileWatcherDetectsAtomicReplacementWithoutWaitingForPolling(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	var activations atomic.Int64
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
		activations.Add(1)
		return nil
	})
	require.NoError(t, err)
	_, failures := fileWatchTestStart(t, reloader, FileWatchOptions{Debounce: 10 * time.Millisecond, PollInterval: time.Hour})
	replacement := filepath.Join(filepath.Dir(filename), "replacement.yaml")
	fileReloadTestWrite(t, replacement, strings.Replace(snapshotTestSource, "original-environment", "atomic-change", 1))
	require.NoError(t, os.Rename(replacement, filename))
	fileWatchTestAwaitBanner(t, reloader, "atomic-change")
	require.EqualValues(t, 1, activations.Load())
	select {
	case err := <-failures:
		t.Fatalf("unexpected reload error: %v", err)
	default:
	}
}

func TestFileWatcherRetainsLastGoodConfigurationAndRecoversFromMissingFile(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error { return nil })
	require.NoError(t, err)
	_, failures := fileWatchTestStart(t, reloader, FileWatchOptions{Debounce: 5 * time.Millisecond, PollInterval: 25 * time.Millisecond})
	original := reloader.Current().Configuration()

	fileReloadTestWrite(t, filename, "flows: [")
	select {
	case err := <-failures:
		require.ErrorContains(t, err, "cannot reload configuration")
	case <-time.After(3 * time.Second):
		t.Fatal("invalid configuration was not reported")
	}
	require.True(t, original.IsEqualTo(reloader.Current().Configuration()))

	require.NoError(t, os.Remove(filename))
	require.Eventually(t, func() bool {
		select {
		case err := <-failures:
			return strings.Contains(err.Error(), "does not exist")
		default:
			return false
		}
	}, 3*time.Second, 5*time.Millisecond)
	require.True(t, original.IsEqualTo(reloader.Current().Configuration()))

	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "recovered-change", 1))
	fileWatchTestAwaitBanner(t, reloader, "recovered-change")
}

func TestFileWatcherPollsExternalSymlinkTargetAndFollowsProjectedRotation(t *testing.T) {
	root := t.TempDir()
	targetDirectory := t.TempDir()
	target := filepath.Join(targetDirectory, "first.yaml")
	fileReloadTestWrite(t, target, snapshotTestSource)
	filename := filepath.Join(root, "configuration.yaml")
	if err := os.Symlink(target, filename); err != nil {
		t.Skipf("creating symlinks is unavailable: %v", err)
	}
	var initial Configuration
	require.NoError(t, initial.LoadFromFile(filename))
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error { return nil })
	require.NoError(t, err)
	fileWatchTestStart(t, reloader, FileWatchOptions{Debounce: 5 * time.Millisecond, PollInterval: 25 * time.Millisecond})

	// This directory is not watched: only periodic rereading can detect it.
	fileReloadTestWrite(t, target, strings.Replace(snapshotTestSource, "original-environment", "target-change", 1))
	fileWatchTestAwaitBanner(t, reloader, "target-change")

	nextTarget := filepath.Join(targetDirectory, "second.yaml")
	fileReloadTestWrite(t, nextTarget, strings.Replace(snapshotTestSource, "original-environment", "projected-change", 1))
	nextLink := filepath.Join(root, "next-link")
	require.NoError(t, os.Symlink(nextTarget, nextLink))
	require.NoError(t, os.Rename(nextLink, filename))
	fileWatchTestAwaitBanner(t, reloader, "projected-change")
}

func TestFileWatcherRestoresWatchAfterParentDirectoryReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "configuration")
	require.NoError(t, os.Mkdir(directory, 0700))
	filename := filepath.Join(directory, "configuration.yaml")
	fileReloadTestWrite(t, filename, snapshotTestSource)
	var initial Configuration
	require.NoError(t, initial.LoadFromFile(filename))
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error { return nil })
	require.NoError(t, err)
	fileWatchTestStart(t, reloader, FileWatchOptions{Debounce: 5 * time.Millisecond, PollInterval: 25 * time.Millisecond})

	require.NoError(t, os.Remove(filename))
	require.NoError(t, os.Remove(directory))
	require.NoError(t, os.Mkdir(directory, 0700))
	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "new-directory", 1))
	fileWatchTestAwaitBanner(t, reloader, "new-directory")
}

func TestFileWatcherRejectsInvalidOptionsAndConcurrentWatch(t *testing.T) {
	_, initial := fileReloadTestConfiguration(t)
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error { return nil })
	require.NoError(t, err)
	observer := func(error) {}
	for _, options := range []FileWatchOptions{
		{},
		{Debounce: -time.Second, OnError: observer},
		{PollInterval: -time.Second, OnError: observer},
	} {
		require.Error(t, reloader.Watch(t.Context(), options))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, reloader.Watch(ctx, FileWatchOptions{OnError: observer}), context.Canceled)

	fileWatchTestStart(t, reloader, FileWatchOptions{Debounce: time.Millisecond, PollInterval: time.Second})
	require.ErrorContains(t, reloader.Watch(t.Context(), FileWatchOptions{OnError: observer}), "already running")
}

func TestFileWatcherReadyBarrierPrecedesReloadAndJoinsCancellation(t *testing.T) {
	for _, cancelBeforeRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "resume", true: "cancel"}[cancelBeforeRelease], func(t *testing.T) {
			filename, initial := fileReloadTestConfiguration(t)
			applied := make(chan struct{}, 1)
			reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
				applied <- struct{}{}
				return nil
			})
			require.NoError(t, err)
			fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "ready-change", 1))
			ctx, cancel := context.WithCancel(t.Context())
			ready, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				done <- reloader.Watch(ctx, FileWatchOptions{
					Debounce: time.Millisecond, PollInterval: 5 * time.Millisecond,
					OnError: func(error) {},
					OnReady: func() {
						close(ready)
						select {
						case <-resume:
						case <-ctx.Done():
						}
					},
				})
			}()
			t.Cleanup(func() { cancel(); require.ErrorIs(t, fileReloadTestRead(t, done), context.Canceled) })
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("watcher did not install native watch")
			}
			require.Never(t, func() bool { return len(applied) != 0 }, 20*time.Millisecond, time.Millisecond)
			if cancelBeforeRelease {
				cancel()
			} else {
				close(resume)
				fileWatchTestAwaitBanner(t, reloader, "ready-change")
				require.Len(t, applied, 1)
			}
		})
	}
}
