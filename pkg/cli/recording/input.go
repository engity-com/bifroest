package recording

import (
	goerrors "errors"
	"fmt"
	stdos "os"
	"strings"

	"github.com/engity-com/bifroest/pkg/recording"
)

func OpenRecordingInput(path string) (*stdos.File, stdos.FileInfo, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return nil, nil, fmt.Errorf("recording command requires a file path")
	}
	initial, err := stdos.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect Recording input %q: %w", path, err)
	}
	if initial.Mode()&stdos.ModeSymlink != 0 || !initial.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("recording input %q must be a regular non-symlink file", path)
	}
	file, err := openRecordingFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open Recording input %q: %w", path, err)
	}
	opened, err := file.Stat()
	if err != nil || !stdos.SameFile(initial, opened) {
		return nil, nil, goerrors.Join(fmt.Errorf("recording input %q changed while opening", path), err, file.Close())
	}
	if opened.Size() < 1 {
		return nil, nil, goerrors.Join(fmt.Errorf("recording input %q is empty", path), file.Close())
	}
	return file, initial, nil
}

// Inspect must have authenticated the snapshot before its signed ID is used.
// A transport header alone cannot bind an artifact to the requested Recording.
func validateExpectedRecordingID(inspection *recording.Inspection, expected recording.Id) error {
	if expected.IsZero() {
		return nil
	}
	if inspection == nil || inspection.Native == nil {
		return fmt.Errorf("remote Recording requires a native sealed Recording artifact")
	}
	if recording.Id(inspection.Native.Header.RecordingId) != expected {
		return fmt.Errorf("remote Recording does not match requested signed ID")
	}
	return nil
}

func ValidateRecordingInput(path string, file *stdos.File, initial stdos.FileInfo) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	current, err := stdos.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot recheck Recording input %q: %w", path, err)
	}
	if current.Mode()&stdos.ModeSymlink != 0 || !current.Mode().IsRegular() || !stdos.SameFile(initial, opened) || !stdos.SameFile(initial, current) || opened.Size() != initial.Size() || current.Size() != initial.Size() || opened.Mode() != initial.Mode() || current.Mode() != initial.Mode() || !opened.ModTime().Equal(initial.ModTime()) || !current.ModTime().Equal(initial.ModTime()) {
		return fmt.Errorf("recording input %q changed while being processed", path)
	}
	return nil
}
