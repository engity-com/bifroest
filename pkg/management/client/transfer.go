package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/fxamacker/cbor/v2"
)

// TransferResponse translates framed artifact data into a Reader EOF while
// retaining the distinct post-driver completion for Complete. The owning HTTP
// adapter must independently validate status/media type/origin/auth scope and
// forbid cookies/redirects. This decoder neither opens requests nor trusts evidence.
type TransferResponse struct {
	body                      io.ReadCloser
	request                   protocol.ArtifactRequest
	mutex                     sync.Mutex
	closeOnce                 sync.Once
	closeErr                  error
	digest                    hash.Hash
	count                     uint64
	pending                   []byte
	started, ended, completed bool
	failure                   error
}

// NewTransferResponse takes ownership of body on success. On constructor error
// the caller still owns it. No I/O occurs before Receive installs cancellation.
func NewTransferResponse(body io.ReadCloser, request protocol.ArtifactRequest) (*TransferResponse, error) {
	if body == nil || request.Validate() != nil {
		return nil, protocol.ErrRequest
	}
	return &TransferResponse{body: body, request: request, digest: sha256.New()}, nil
}

func (this *TransferResponse) begin() error {
	if this.started {
		return nil
	}
	this.started = true
	magic := make([]byte, len(wire.TransferMagic))
	if _, err := io.ReadFull(this.body, magic); err != nil {
		return fmt.Errorf("incomplete artifact transfer magic: %w", err)
	}
	if string(magic) != wire.TransferMagic {
		return fmt.Errorf("invalid artifact transfer magic")
	}
	return nil
}

func (this *TransferResponse) frame() (byte, uint32, error) {
	var header [5]byte
	if _, err := io.ReadFull(this.body, header[:]); err != nil {
		return 0, 0, err
	}
	return header[0], binary.BigEndian.Uint32(header[1:]), nil
}

func (this *TransferResponse) Read(data []byte) (n int, err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	defer func() {
		if err != nil && err != io.EOF {
			this.failure = err
		}
	}()
	if this.failure != nil {
		return 0, this.failure
	}
	if len(data) == 0 {
		return 0, nil
	}
	if err := this.begin(); err != nil {
		return 0, err
	}
	if len(this.pending) > 0 {
		n = copy(data, this.pending)
		this.pending = this.pending[n:]
		return n, nil
	}
	if this.ended {
		return 0, io.EOF
	}
	kind, size, err := this.frame()
	if err != nil {
		return 0, fmt.Errorf("artifact data ended before data-end frame: %w", err)
	}
	if kind == wire.TransferDataEnd && size == 0 {
		this.ended = true
		return 0, io.EOF
	}
	if kind != wire.TransferData || size == 0 || size > wire.MaximumTransferFrameBytes || this.count+uint64(size) > uint64(wire.MaximumTransferBytes(this.request)) {
		return 0, fmt.Errorf("invalid artifact data frame")
	}
	this.pending = make([]byte, size)
	if _, err := io.ReadFull(this.body, this.pending); err != nil {
		this.pending = nil
		return 0, fmt.Errorf("incomplete artifact data frame: %w", err)
	}
	_, _ = this.digest.Write(this.pending)
	this.count += uint64(size)
	n = copy(data, this.pending)
	this.pending = this.pending[n:]
	return n, nil
}

func (this *TransferResponse) Complete() (err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	defer func() {
		if err != nil {
			this.failure = err
		}
	}()
	if this.failure != nil {
		return this.failure
	}
	if !this.ended || len(this.pending) != 0 || this.completed {
		return fmt.Errorf("artifact transfer data was not completely consumed or completion was reused")
	}
	this.completed = true
	kind, size, err := this.frame()
	if err != nil {
		return fmt.Errorf("artifact task completion is missing: %w", err)
	}
	if kind != wire.TransferComplete || size == 0 || size > wire.MaximumTransferCompletionBytes {
		return fmt.Errorf("invalid artifact completion frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(this.body, data); err != nil {
		return err
	}
	mode, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return err
	}
	var completion wire.TransferCompletion
	if err := mode.Unmarshal(data, &completion); err != nil {
		return err
	}
	canonical, err := cbor.Marshal(completion)
	var digest [sha256.Size]byte
	copy(digest[:], this.digest.Sum(nil))
	if err != nil || !bytes.Equal(canonical, data) || completion.Version != 1 || completion.Request != this.request || completion.Bytes != this.count || completion.SHA256 != digest {
		return fmt.Errorf("artifact completion does not match request or data")
	}
	var trailing [1]byte
	if _, err := io.ReadFull(this.body, trailing[:]); err != io.EOF {
		return fmt.Errorf("artifact completion has trailing data or failed before EOF: %v", err)
	}
	return nil
}

// Abort never takes the reader lock: body.Close must interrupt blocked reads.
// The receiver joins cancellation before Close releases the same owned body.
func (this *TransferResponse) Abort() error { return this.Close() }
func (this *TransferResponse) Close() error {
	this.closeOnce.Do(func() { this.closeErr = this.body.Close() })
	return this.closeErr
}
