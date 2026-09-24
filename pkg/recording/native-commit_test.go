package recording

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type nativeCommitTestFile struct {
	*os.File
	syncs, failAt int
}

func (f *nativeCommitTestFile) Sync() error {
	f.syncs++
	if f.syncs == f.failAt {
		return errors.New("injected frame sync failure")
	}
	return f.File.Sync()
}

func TestNativeDurableRecordingOutputCommitsEveryFrame(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	file, err := os.OpenFile(t.TempDir()+"/native.bcast", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = NewNativeRecordingWriter(file, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.ErrorContains(t, err, "durable unit-commit sink")
	output, err := NewNativeDurableRecordingOutput(file)
	require.NoError(t, err)
	writer, err := NewNativeRecordingWriter(output, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("durable")))
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusIncomplete, EndedAt: metadata.StartedAt.Add(time.Second)}, nil)
	require.NoError(t, err)
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	verified, err := VerifyNativeRecordingOuter(file, size, NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, uint8(3), verified.Seal.Status)
	headerUnit, offset, tail, err := nativeformat.ReadUnitAt(file, int64(len(nativeformat.RecordingMagic)), size, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.False(t, tail)
	checkpoint, err := VerifyNativeRecordingHead(head, headerUnit.Payload)
	require.NoError(t, err)
	require.Greater(t, checkpoint.PrefixBytes, uint64(offset))
	for offset < size {
		_, next, uncommitted, err := nativeformat.ReadUnitAt(file, offset, size, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		require.False(t, uncommitted)
		offset = next
	}
	require.Equal(t, size, offset)
	_, err = NewNativeDurableRecordingOutput(file)
	require.Error(t, err, "existing file cannot be reused as a new recording")
}

func TestNativeDurableRecordingOutputCrashBetweenBodyAndCommit(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	file, err := os.OpenFile(t.TempDir()+"/interrupted.bcast", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	backend := &nativeCommitTestFile{File: file, failAt: 2} // magic sync succeeds; header body sync fails
	output := &NativeDurableRecordingOutput{file: backend}
	_, err = NewNativeRecordingWriter(output, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.ErrorContains(t, err, "injected frame sync failure")
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	var magic [len(nativeformat.RecordingMagic)]byte
	_, err = file.ReadAt(magic[:], 0)
	require.NoError(t, err)
	require.Equal(t, nativeformat.RecordingMagic, string(magic[:]))
	_, _, tail, err := nativeformat.ReadUnitAt(file, int64(len(magic)), size, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.True(t, tail, "state-0 header cannot be mistaken for a committed header")
	require.Error(t, output.CommitNativeRecordingUnit(bytes.Repeat([]byte{1}, 18)), "failed sink is poisoned")
}

func TestNativeDurableRecordingOutputRejectsCommittedCorruption(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	file, err := os.OpenFile(t.TempDir()+"/tampered.bcast", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	output, err := NewNativeDurableRecordingOutput(file)
	require.NoError(t, err)
	_, err = NewNativeRecordingWriter(output, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte{0}, int64(len(nativeformat.RecordingMagic))+6)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	_, _, tail, err := nativeformat.ReadUnitAt(file, int64(len(nativeformat.RecordingMagic)), size, nativeformat.MaxMetadataPayload)
	require.Error(t, err, "state-1 frame with invalid CRC cannot be truncated as a tail")
	require.False(t, tail)
}

func TestNativeDurableRecordingOutputRejectsAppendMode(t *testing.T) {
	file, err := os.OpenFile(t.TempDir()+"/append.bcast", os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = NewNativeDurableRecordingOutput(file)
	require.Error(t, err)
}
