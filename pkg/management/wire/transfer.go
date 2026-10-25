package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/fxamacker/cbor/v2"
)

const TransferMediaType = "application/vnd.bifroest.management-transfer.v1"
const TransferMagic = "bifroest-management-transfer-v1\n"
const MaximumTransferFrameBytes = 32 << 10
const MaximumTransferCompletionBytes = 4096
const (
	TransferData     byte = 1
	TransferDataEnd  byte = 2
	TransferComplete byte = 3
)

// TransferCompletion is a post-driver success assertion bound to exact request
// selectors and transferred bytes. It is not an evidence signature/trust proof.
type TransferCompletion struct {
	Version uint8                    `cbor:"1,keyasint"`
	Request protocol.ArtifactRequest `cbor:"2,keyasint"`
	Bytes   uint64                   `cbor:"3,keyasint"`
	SHA256  [sha256.Size]byte        `cbor:"4,keyasint"`
}

func MaximumTransferBytes(request protocol.ArtifactRequest) int64 {
	switch request.Operation {
	case protocol.DownloadRecording:
		return protocol.MaximumRecordingArtifactBytes + maxRecordingHeaderBytes + 4
	case protocol.DownloadAudit:
		return MaxAuditSnapshotBytes + MaxAuditSnapshotHeaderBytes + 4
	default:
		return 0
	}
}

// TransferWriter carries the unchanged legacy artifact envelope inside bounded
// data frames. EndData is NOT success. Complete must only be called by the owning
// transport after successful task/recording-seal/final-audit and access checks.
// Single producer; no automatic retry after any output error.
type TransferWriter struct {
	mutex                     sync.Mutex
	output                    io.Writer
	request                   protocol.ArtifactRequest
	digest                    hash.Hash
	count                     uint64
	maximum                   int64
	started, ended, completed bool
	failure                   error
}

func NewTransferWriter(output io.Writer, request protocol.ArtifactRequest) (*TransferWriter, error) {
	if request.Validate() != nil || output == nil {
		return nil, protocol.ErrRequest
	}
	return &TransferWriter{output: output, request: request, digest: sha256.New(), maximum: MaximumTransferBytes(request)}, nil
}

func (this *TransferWriter) begin() error {
	if this.failure != nil {
		return this.failure
	}
	if !this.started {
		this.started = true
		_, this.failure = io.Copy(this.output, bytes.NewBufferString(TransferMagic))
	}
	return this.failure
}

func (this *TransferWriter) frame(kind byte, data []byte) error {
	if err := this.begin(); err != nil {
		return err
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := io.Copy(this.output, bytes.NewReader(header[:])); err != nil {
		this.failure = err
		return err
	}
	_, this.failure = io.Copy(this.output, bytes.NewReader(data))
	return this.failure
}

func (this *TransferWriter) Write(data []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.failure != nil {
		return 0, this.failure
	}
	if this.ended || this.completed {
		return 0, fmt.Errorf("transfer data already ended")
	}
	if uint64(len(data)) > uint64(this.maximum)-this.count {
		this.failure = fmt.Errorf("artifact transfer exceeds data bound")
		return 0, this.failure
	}
	written := 0
	for len(data) > 0 {
		size := min(len(data), MaximumTransferFrameBytes)
		part := data[:size]
		if err := this.frame(TransferData, part); err != nil {
			return written, err
		}
		_, _ = this.digest.Write(part)
		this.count += uint64(size)
		written += size
		data = data[size:]
	}
	return written, nil
}

func (this *TransferWriter) EndData() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.ended || this.completed {
		return fmt.Errorf("transfer data already ended")
	}
	if err := this.frame(TransferDataEnd, nil); err != nil {
		return err
	}
	this.ended = true
	return nil
}

func (this *TransferWriter) Complete() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.failure != nil {
		return this.failure
	}
	if !this.ended || this.completed {
		return fmt.Errorf("transfer is not awaiting completion")
	}
	this.completed = true
	completion := TransferCompletion{Version: 1, Request: this.request, Bytes: this.count}
	copy(completion.SHA256[:], this.digest.Sum(nil))
	data, err := cbor.Marshal(completion)
	if err != nil || len(data) > MaximumTransferCompletionBytes {
		return fmt.Errorf("invalid transfer completion")
	}
	return this.frame(TransferComplete, data)
}
