//go:build windows && io_probe

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Diagnostic-branch-only probe. It exercises the real Windows filesystem
// helpers without changing production persistence or any existing test.
// Output is bounded and contains only fixed operation names and durations.
func TestWindowsDurableArtifactIOProbe(t *testing.T) {
	const samples = 16
	t.Logf("io-probe temp-volume=%s runner-temp-volume=%s",
		filepath.VolumeName(os.TempDir()), filepath.VolumeName(os.Getenv("RUNNER_TEMP")))
	directory := t.TempDir()
	lockDirectory := t.TempDir()
	payload := bytes.Repeat([]byte("synthetic-io-probe"), 64)
	timings := make(map[string][]time.Duration)
	measure := func(name string, operation func() error) {
		t.Helper()
		started := time.Now()
		err := operation()
		timings[name] = append(timings[name], time.Since(started))
		if err != nil {
			t.Fatalf("operation=%s failed", name)
		}
	}
	for range samples {
		var lock *journalProcessLock
		lockPath := filepath.Join(lockDirectory, "probe.lock")
		measure("lock.acquire", func() (err error) {
			lock, err = acquireJournalProcessLock(lockPath, journalFileMode)
			return
		})
		measure("lock.validate", func() error {
			same, err := sameJournalProcessLockFile(lock.file, lockPath)
			if err == nil && !same {
				t.Fatal("operation=lock.validate identity mismatch")
			}
			return err
		})
		measure("lock.close", lock.Close)

		temporary := filepath.Join(directory, remoteArtifactLifecycleTempName)
		var file *os.File
		measure("temporary.remove", func() error {
			return removeRemoteArtifactReceiptFile(temporary, directory)
		})
		measure("file.create", func() (err error) {
			file, err = os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
			return
		})
		measure("file.secure", func() error { return secureJournalFile(temporary, file) })
		measure("file.write", func() error {
			written, err := file.Write(payload)
			if err == nil && written != len(payload) {
				t.Fatal("operation=file.write short write")
			}
			return err
		})
		measure("file.flush", file.Sync)
		measure("file.close", file.Close)
		target := filepath.Join(directory, remoteArtifactLifecycleFileName)
		measure("file.replace.write-through", func() error { return replaceJournalFile(temporary, target) })
		measure("directory.sync", func() error { return syncJournalDirectory(directory) })
		measure("state.usage", func() error {
			_, err := remoteArtifactReceiptStateUsage(directory)
			return err
		})
		measure("published.read", func() error {
			actual, err := os.ReadFile(target)
			if err == nil && !bytes.Equal(actual, payload) {
				t.Fatal("operation=published.read content mismatch")
			}
			return err
		})
		measure("lifecycle.write.total", func() error {
			return writeRemoteArtifactLifecycle(directory, "synthetic.bcast", payload, nil)
		})
		measure("receipt.write.total", func() error {
			return writeRemoteArtifactReceipt(directory, "synthetic.bcast", payload, nil)
		})
	}
	names := make([]string, 0, len(timings))
	for name := range timings {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		values := timings[name]
		slices.Sort(values)
		var total time.Duration
		for _, value := range values {
			total += value
		}
		t.Logf("io-probe operation=%s count=%d total=%v p50=%v p95=%v max=%v",
			name, len(values), total, values[(len(values)-1)/2], values[(len(values)*95-1)/100], values[len(values)-1])
	}
}
