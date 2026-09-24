package recording

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// NativeRecordingUnitCommitter is an optional io.Writer extension. Its Write
// method accepts and syncs only the recording magic; each encoded unit is
// handed to CommitNativeRecordingUnit in its state-1 form. The implementation
// must sync the complete state-0 frame before writing and syncing state 1.
type NativeRecordingUnitCommitter interface {
	io.Writer
	CommitNativeRecordingUnit(frame []byte) error
}

// NativeDurableRecordingOutput requires an exclusively owned, empty, regular
// read/write file opened WITHOUT O_APPEND. It doesn't own the file or sync its
// parent directory; the repository adapter must do both directory sync and
// atomic head replacement before publishing. Any failure poisons the sink.
type NativeDurableRecordingOutput struct {
	file    nativeCommitFile
	offset  int64
	poison  error
	started bool
}

type nativeCommitFile interface {
	io.WriterAt
	Sync() error
	Stat() (os.FileInfo, error)
}

func NewNativeDurableRecordingOutput(file nativeCommitFile) (*NativeDurableRecordingOutput, error) {
	if file == nil {
		return nil, fmt.Errorf("missing native recording file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return nil, fmt.Errorf("native recording file must be an empty regular file: %v", err)
	}
	if _, err := file.WriteAt(nil, 0); err != nil {
		return nil, fmt.Errorf("native recording file must be writable without O_APPEND: %w", err)
	}
	return &NativeDurableRecordingOutput{file: file}, nil
}

func (d *NativeDurableRecordingOutput) fail(err error) error {
	if d.poison == nil {
		d.poison = err
	}
	return d.poison
}

func (d *NativeDurableRecordingOutput) Write(value []byte) (int, error) {
	if d == nil {
		return 0, fmt.Errorf("missing native recording commit sink")
	}
	if d.poison != nil {
		return 0, d.poison
	}
	if d.started || string(value) != nativeformat.RecordingMagic {
		return 0, d.fail(fmt.Errorf("native recording commit sink accepts only the initial magic via Write"))
	}
	n, err := d.file.WriteAt(value, 0)
	if err != nil {
		return n, d.fail(err)
	}
	if n != len(value) {
		return n, d.fail(io.ErrShortWrite)
	}
	if err := d.file.Sync(); err != nil {
		return n, d.fail(err)
	}
	d.started, d.offset = true, int64(n)
	return n, nil
}

func (d *NativeDurableRecordingOutput) CommitNativeRecordingUnit(frame []byte) error {
	if d == nil {
		return fmt.Errorf("missing native recording commit sink")
	}
	if d.poison != nil {
		return d.poison
	}
	if !d.started || len(frame) < 18 || frame[5] != 1 {
		return d.fail(fmt.Errorf("native recording unit must follow the synced magic in state 1"))
	}
	unit, end, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(frame), 0, int64(len(frame)), nativeformat.MaxRecordingChunkPayload)
	if err != nil || tail || end != int64(len(frame)) || unit.Type == 0 {
		return d.fail(fmt.Errorf("invalid native recording unit for commit: %v", err))
	}
	info, err := d.file.Stat()
	if err != nil || info.Size() != d.offset {
		return d.fail(fmt.Errorf("native recording file changed between commits: %v", err))
	}
	// CRC excludes the commit byte: the final physical bytes equal frame exactly.
	staged := bytes.Clone(frame)
	staged[5] = 0
	n, err := d.file.WriteAt(staged, d.offset)
	if err != nil {
		return d.fail(err)
	}
	if n != len(staged) {
		return d.fail(io.ErrShortWrite)
	}
	if err := d.file.Sync(); err != nil {
		return d.fail(err)
	}
	n, err = d.file.WriteAt([]byte{1}, d.offset+5)
	if err != nil {
		return d.fail(err)
	}
	if n != 1 {
		return d.fail(io.ErrShortWrite)
	}
	if err := d.file.Sync(); err != nil {
		return d.fail(err)
	}
	d.offset += int64(len(frame))
	return nil
}
