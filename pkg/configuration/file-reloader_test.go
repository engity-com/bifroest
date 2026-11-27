package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fileReloadTestConfiguration(t *testing.T) (string, Configuration) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "configuration.yaml")
	fileReloadTestWrite(t, filename, snapshotTestSource)
	var initial Configuration
	require.NoError(t, initial.LoadFromFile(filename))
	return filename, initial
}

func fileReloadTestWrite(t *testing.T, filename, source string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filename, []byte(source), 0600))
}

func fileReloadTestRead(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not complete")
		return nil
	}
}

func TestFileReloaderRequiresFileSourceAndRuntimeCallback(t *testing.T) {
	_, conf := fileReloadTestConfiguration(t)
	_, err := NewFileReloader(conf, nil)
	require.ErrorContains(t, err, "activation callback")
	conf.Filename = ""
	_, err = NewFileReloader(conf, func(context.Context, *Snapshot, ReloadChanges) error { return nil })
	require.ErrorContains(t, err, "file source")
}

func TestFileReloaderRetainsLastAcceptedSnapshotOnFailureAndRecovers(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	var activations int
	rejected := errors.New("restart required")
	reloader, err := NewFileReloader(initial, func(_ context.Context, next *Snapshot, changes ReloadChanges) error {
		activations++
		require.True(t, changes.RuntimeChanged())
		require.Equal(t, "new-environment", next.Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
		if activations == 1 {
			return rejected
		}
		return nil
	})
	require.NoError(t, err)
	original := reloader.Current()

	for _, source := range []string{
		"flows: [",
		strings.Replace(snapshotTestSource, "environment: shared", "environment: missing", 1),
		snapshotTestSource + "\n---\nflows: [",
		snapshotTestSource + "\n---\n" + referenceTestInlineFlow,
	} {
		fileReloadTestWrite(t, filename, source)
		_, err = reloader.Reload(t.Context())
		require.Error(t, err)
		require.Same(t, original, reloader.Current())
		require.Zero(t, activations)
	}
	require.NoError(t, os.Remove(filename))
	_, err = reloader.Reload(t.Context())
	require.Error(t, err)
	require.Same(t, original, reloader.Current())

	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "new-environment", 1))
	changes, err := reloader.Reload(t.Context())
	require.ErrorIs(t, err, rejected)
	require.True(t, changes.RuntimeChanged())
	require.Same(t, original, reloader.Current())

	_, err = reloader.Reload(t.Context())
	require.NoError(t, err)
	require.Equal(t, 2, activations)
	require.NotSame(t, original, reloader.Current())
	require.Equal(t, "new-environment", reloader.Current().Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
	require.Equal(t, "original-environment", original.Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
}

func TestFileReloaderAcceptsDeclarationOnlyChangesWithoutRuntimeActivation(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
		t.Error("unused root definition must not prepare new runtime resources")
		return nil
	})
	require.NoError(t, err)
	changes, err := reloader.Reload(t.Context())
	require.NoError(t, err)
	require.False(t, changes.Changed)

	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "unused-environment", "changed-unused-environment", 1))
	changes, err = reloader.Reload(t.Context())
	require.NoError(t, err)
	require.True(t, changes.Changed)
	require.False(t, changes.RuntimeChanged())
	require.Equal(t, "changed-unused-environment", reloader.Current().Configuration().Environments["unused"].V.(*EnvironmentDummy).Banner.String())
}

func TestFileReloaderQueuedRequestReadsLatestFileAndSerializesActivation(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var active, calls atomic.Int64
	var observed []string
	var mutex sync.Mutex
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	reloader, err := NewFileReloader(initial, func(ctx context.Context, next *Snapshot, _ ReloadChanges) error {
		if active.Add(1) != 1 {
			t.Error("runtime activation callbacks overlapped")
		}
		defer active.Add(-1)
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		mutex.Lock()
		observed = append(observed, next.Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
		mutex.Unlock()
		return nil
	})
	require.NoError(t, err)

	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "first-change", 1))
	first := make(chan error, 1)
	go func() { _, err := reloader.Reload(t.Context()); first <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first activation did not start")
	}

	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "superseded-change", 1))
	second := make(chan error, 1)
	go func() { _, err := reloader.Reload(t.Context()); second <- err }()
	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "latest-change", 1))
	unblock()

	require.NoError(t, fileReloadTestRead(t, first))
	require.NoError(t, fileReloadTestRead(t, second))
	mutex.Lock()
	require.Equal(t, []string{"first-change", "latest-change"}, observed)
	mutex.Unlock()
	require.Equal(t, "latest-change", reloader.Current().Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
}

func TestFileReloaderCancellationWhileWaitingDoesNotActivate(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
		t.Error("a canceled request must not activate a configuration")
		return nil
	})
	require.NoError(t, err)
	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "new-environment", 1))
	original := reloader.Current()

	// Hold the gate to exercise cancellation without depending on timing.
	reloader.gate <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := reloader.Reload(ctx); done <- err }()
	cancel()
	require.ErrorIs(t, fileReloadTestRead(t, done), context.Canceled)
	require.Same(t, original, reloader.Current())
	<-reloader.gate

	_, err = reloader.Reload(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, original, reloader.Current())
}

func TestFileReloaderPublishesCommittedActivationEvenIfContextWasCanceled(t *testing.T) {
	filename, initial := fileReloadTestConfiguration(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
		cancel() // Activation has committed; returning nil is authoritative.
		return nil
	})
	require.NoError(t, err)
	fileReloadTestWrite(t, filename, strings.Replace(snapshotTestSource, "original-environment", "committed-change", 1))
	_, err = reloader.Reload(ctx)
	require.NoError(t, err)
	require.Equal(t, "committed-change", reloader.Current().Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
}

func TestFileReloaderFollowsAtomicReplacementAndSymlinkRotation(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "atomic replacement", true: "symlink rotation"}[symlink], func(t *testing.T) {
			filename, initial := fileReloadTestConfiguration(t)
			var calls int
			reloader, err := NewFileReloader(initial, func(context.Context, *Snapshot, ReloadChanges) error {
				calls++
				return nil
			})
			require.NoError(t, err)
			next := filepath.Join(filepath.Dir(filename), "next.yaml")
			fileReloadTestWrite(t, next, strings.Replace(snapshotTestSource, "original-environment", "rotated-change", 1))
			if symlink {
				link := filepath.Join(filepath.Dir(filename), "link.yaml")
				if err := os.Symlink(next, link); err != nil {
					t.Skipf("creating symlinks is unavailable: %v", err)
				}
				require.NoError(t, os.Rename(link, filename))
			} else {
				require.NoError(t, os.Rename(next, filename))
			}
			_, err = reloader.Reload(t.Context())
			require.NoError(t, err)
			require.Equal(t, 1, calls)
			require.Equal(t, "rotated-change", reloader.Current().Configuration().Flows[0].Environment.V.(*EnvironmentDummy).Banner.String())
		})
	}
}
