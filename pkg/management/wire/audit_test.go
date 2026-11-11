package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

type memoryAuditSink struct {
	header                                AuditSnapshotHeader
	files                                 map[string]*memoryAuditFile
	begins, opens                         int
	beginErr, openErr, writeErr, closeErr error
	mutateHeader                          bool
}
type memoryAuditFile struct {
	bytes.Buffer
	closes             int
	writeErr, closeErr error
}

func (this *memoryAuditFile) Write(p []byte) (int, error) {
	if this.writeErr != nil {
		return 0, this.writeErr
	}
	return this.Buffer.Write(p)
}
func (this *memoryAuditFile) Close() error { this.closes++; return this.closeErr }
func (this *memoryAuditSink) Begin(header AuditSnapshotHeader) error {
	this.begins++
	this.header = header
	this.files = map[string]*memoryAuditFile{}
	if this.mutateHeader {
		header.Files[0].Name = "../not-the-decoder-input"
		header.Files[0].Size = 1
		header.Files[0].SHA256 = strings.Repeat("0", 64)
	}
	return this.beginErr
}
func (this *memoryAuditSink) Open(entry AuditSnapshotEntry) (io.WriteCloser, error) {
	this.opens++
	if this.openErr != nil {
		return nil, this.openErr
	}
	file := &memoryAuditFile{writeErr: this.writeErr, closeErr: this.closeErr}
	this.files[entry.Name] = file
	return file, nil
}

func auditTransferFixture() (AuditSnapshotHeader, []byte) {
	// Deliberately not signed evidence: transfer digests never establish trust.
	contents := [][]byte{[]byte("untrusted checkpoint bytes"), []byte("untrusted encrypted segment bytes")}
	header := AuditSnapshotHeader{Version: 1, Name: "default", Producer: strings.Repeat("a", 64), Recipient: "untrusted recipient assertion"}
	for index, name := range []string{"head.cbor", "active.beaudit"} {
		digest := sha256.Sum256(contents[index])
		header.Files = append(header.Files, AuditSnapshotEntry{Name: name, Size: int64(len(contents[index])), SHA256: hex.EncodeToString(digest[:])})
	}
	return header, bytes.Join(contents, nil)
}
func auditTransferBytes(t *testing.T, header AuditSnapshotHeader, content []byte) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(header)
	require.NoError(t, err)
	var result bytes.Buffer
	require.NoError(t, binary.Write(&result, binary.BigEndian, uint32(len(encoded))))
	result.Write(encoded)
	result.Write(content)
	return result.Bytes()
}

func TestAuditTransferUsesProvisionalPortableSinkAndIndependentHeader(t *testing.T) {
	header, content := auditTransferFixture()
	for _, mutate := range []bool{false, true} {
		sink := &memoryAuditSink{mutateHeader: mutate}
		decoded, err := ReadAuditSnapshot(bytes.NewReader(auditTransferBytes(t, header, content)), sink)
		require.NoError(t, err)
		require.Equal(t, header, decoded)
		require.Equal(t, 1, sink.begins)
		require.Equal(t, len(header.Files), sink.opens)
		var copied bytes.Buffer
		for _, entry := range header.Files {
			file := sink.files[entry.Name]
			require.NotNil(t, file)
			require.Equal(t, 1, file.closes)
			require.Equal(t, entry.Size, int64(file.Len()))
			copied.Write(file.Bytes())
		}
		require.Equal(t, content, copied.Bytes())
	}
	var encoded bytes.Buffer
	require.NoError(t, WriteAuditSnapshotHeader(&encoded, header))
	encoded.Write(content)
	require.Equal(t, auditTransferBytes(t, header, content), encoded.Bytes(), "existing v1 CBOR framing must remain byte-identical")
	require.ErrorIs(t, WriteAuditSnapshotHeader(shortRecordingStreamWriter{}, header), io.ErrShortWrite)
}

func TestAuditTransferPreflightsEntireHeaderBeforeBeginningAnySink(t *testing.T) {
	base, content := auditTransferFixture()
	for _, change := range []func(*AuditSnapshotHeader){
		func(h *AuditSnapshotHeader) { h.Version = 2 }, func(h *AuditSnapshotHeader) { h.Name = "" }, func(h *AuditSnapshotHeader) { h.Producer = "../" + strings.Repeat("a", 61) }, func(h *AuditSnapshotHeader) { h.Files = nil },
		func(h *AuditSnapshotHeader) { h.Files = h.Files[1:] }, func(h *AuditSnapshotHeader) { h.Files = append(h.Files, h.Files[0]) },
		func(h *AuditSnapshotHeader) { h.Files[1].Size = 0 }, func(h *AuditSnapshotHeader) { h.Files[1].Size = -1 }, func(h *AuditSnapshotHeader) { h.Files[1].Size = MaxAuditSnapshotFileBytes + 1 },
		func(h *AuditSnapshotHeader) { h.Files[1].SHA256 = "not a digest" }, func(h *AuditSnapshotHeader) { h.Files[1].SHA256 = strings.Repeat("A", 64) },
		func(h *AuditSnapshotHeader) { h.Files[1].Name = "../escape.beaudit" }, func(h *AuditSnapshotHeader) { h.Files[1].Name = `segment-alternate:stream.beaudit` }, func(h *AuditSnapshotHeader) { h.Files[1].Name = "segment-null\x00.beaudit" }, func(h *AuditSnapshotHeader) { h.Files[1].Name = "segment-control\n.beaudit" },
		func(h *AuditSnapshotHeader) { h.Recipient = "" },
		func(h *AuditSnapshotHeader) {
			for i := 0; i < 64; i++ {
				h.Files = append(h.Files, AuditSnapshotEntry{Name: fmt.Sprintf("segment-%02d.beaudit", i), Size: MaxAuditSnapshotFileBytes, SHA256: strings.Repeat("0", 64)})
			}
		},
	} {
		header := base
		header.Files = append([]AuditSnapshotEntry(nil), base.Files...)
		change(&header)
		sink := &memoryAuditSink{}
		_, err := ReadAuditSnapshot(bytes.NewReader(auditTransferBytes(t, header, content)), sink)
		require.Error(t, err)
		require.Zero(t, sink.begins)
		require.Zero(t, sink.opens)
		var encoded bytes.Buffer
		require.Error(t, WriteAuditSnapshotHeader(&encoded, header))
		require.Zero(t, encoded.Len())
	}
}

func TestAuditTransferRejectsMalformedDuplicateAndOversizedHeaders(t *testing.T) {
	header, content := auditTransferFixture()
	valid := auditTransferBytes(t, header, content)
	for _, data := range [][]byte{nil, {0, 0}, {0, 0, 0, 0}, {0, 64, 0, 1}, valid[:7], {0, 0, 0, 1, 0xff}} {
		sink := &memoryAuditSink{}
		_, err := ReadAuditSnapshot(bytes.NewReader(data), sink)
		require.Error(t, err)
		require.Zero(t, sink.begins)
	}
	encoded, err := cbor.Marshal(header)
	require.NoError(t, err)
	require.Equal(t, byte(0xa5), encoded[0])
	encoded[0] = 0xa6
	encoded = append(encoded, 1, 1)
	var wire bytes.Buffer
	require.NoError(t, binary.Write(&wire, binary.BigEndian, uint32(len(encoded))))
	wire.Write(encoded)
	wire.Write(content)
	sink := &memoryAuditSink{}
	_, err = ReadAuditSnapshot(&wire, sink)
	require.Error(t, err)
	require.Zero(t, sink.begins)
}

type transferErrorReader struct{ err error }

func (this transferErrorReader) Read([]byte) (int, error) { return 0, this.err }

func TestAuditTransferRequiresExactPayloadDigestsAndFinalEOF(t *testing.T) {
	header, content := auditTransferFixture()
	valid := auditTransferBytes(t, header, content)
	broken := bytes.Clone(valid)
	broken[len(broken)-1] ^= 1
	for _, data := range [][]byte{valid[:len(valid)-1], append(bytes.Clone(valid), 0), broken} {
		sink := &memoryAuditSink{}
		_, err := ReadAuditSnapshot(bytes.NewReader(data), sink)
		require.Error(t, err)
		for _, file := range sink.files {
			require.Equal(t, 1, file.closes)
		}
	}
	failure := errors.New("transport failed after payload")
	_, err := ReadAuditSnapshot(io.MultiReader(bytes.NewReader(valid), transferErrorReader{failure}), &memoryAuditSink{})
	require.ErrorContains(t, err, failure.Error())
}

func TestAuditTransferPreservesSinkFailuresAndClosesEveryOpenedFile(t *testing.T) {
	header, content := auditTransferFixture()
	valid := auditTransferBytes(t, header, content)
	failure := errors.New("local sink failed")
	closeFailure := errors.New("local sink close failed")
	for _, sink := range []*memoryAuditSink{{beginErr: failure}, {openErr: failure}, {writeErr: failure, closeErr: closeFailure}, {closeErr: closeFailure}} {
		_, err := ReadAuditSnapshot(bytes.NewReader(valid), sink)
		require.Error(t, err)
		if sink.beginErr != nil {
			require.Zero(t, sink.opens)
		}
		if sink.beginErr != nil || sink.openErr != nil || sink.writeErr != nil {
			require.ErrorIs(t, err, failure)
		}
		if sink.closeErr != nil {
			require.ErrorIs(t, err, closeFailure)
		}
		for _, file := range sink.files {
			require.Equal(t, 1, file.closes)
		}
	}
}
