package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path"
	"reflect"

	"github.com/engity-com/bifroest/pkg/errors"
)

// SegmentHash is the domain-separated hash bound to a sealed segment's file
// name. It is not a plain SHA-256 checksum of the file contents.
type SegmentHash [sha256.Size]byte

func (this SegmentHash) String() string {
	return hex.EncodeToString(this[:])
}

func (this SegmentHash) IsZero() bool {
	return this == SegmentHash{}
}

func (this SegmentHash) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *SegmentHash) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return errors.Config.Newf("illegal audit segment hash length: %d", len(text))
	}
	var decoded SegmentHash
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal audit segment hash: %w", err)
	}
	*this = decoded
	return nil
}

// SealedSegment describes one immutable, locally verified journal segment.
// Content returns a fresh view positioned at offset zero. Targets must not
// retain or close that view and must publish synchronously before returning.
type SealedSegment struct {
	producerId ProducerId
	sequence   uint64
	hash       SegmentHash
	size       int64
	content    io.ReaderAt
}

func (this SealedSegment) Validate() error {
	if this.producerId.IsZero() {
		return errors.System.Newf("sealed audit segment producer ID is empty")
	}
	if this.sequence == 0 {
		return errors.System.Newf("sealed audit segment sequence is empty")
	}
	if this.hash.IsZero() {
		return errors.System.Newf("sealed audit segment hash is empty")
	}
	if this.size <= 0 {
		return errors.System.Newf("sealed audit segment size must be positive")
	}
	if isNilRemoteValue(this.content) {
		return errors.System.Newf("sealed audit segment content is nil")
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(journalSegmentHashDomain))
	written, err := io.Copy(hasher, io.NewSectionReader(this.content, 0, this.size))
	if err != nil {
		return errors.System.Newf("cannot hash sealed audit segment content: %w", err)
	}
	if written != this.size {
		return errors.System.Newf("sealed audit segment content size is %d instead of %d", written, this.size)
	}
	var extra [1]byte
	read, readErr := this.content.ReadAt(extra[:], this.size)
	if read != 0 || readErr == nil {
		return errors.System.Newf("sealed audit segment content exceeds declared size %d", this.size)
	}
	if readErr != io.EOF {
		return errors.System.Newf("cannot verify sealed audit segment content size: %w", readErr)
	}
	var actualHash SegmentHash
	copy(actualHash[:], hasher.Sum(nil))
	if actualHash != this.hash {
		return errors.System.Newf("sealed audit segment content does not match hash %s", this.hash)
	}
	return nil
}

func newSealedSegment(producerId ProducerId, sequence uint64, hash SegmentHash, size int64, content io.ReaderAt) (SealedSegment, error) {
	result := SealedSegment{producerId: producerId, sequence: sequence, hash: hash, size: size, content: content}
	if err := result.Validate(); err != nil {
		return SealedSegment{}, err
	}
	return result, nil
}

func (this SealedSegment) ProducerId() ProducerId {
	return this.producerId
}

func (this SealedSegment) Sequence() uint64 {
	return this.sequence
}

func (this SealedSegment) Hash() SegmentHash {
	return this.hash
}

func (this SealedSegment) Size() int64 {
	return this.size
}

func (this SealedSegment) Content() io.ReadSeeker {
	if isNilRemoteValue(this.content) || this.size <= 0 {
		return nil
	}
	return io.NewSectionReader(this.content, 0, this.size)
}

func (this SealedSegment) FileName() string {
	return sealedJournalFileName(this.sequence, journalHash(this.hash))
}

func (this SealedSegment) RemotePath() string {
	return path.Join(this.producerId.String(), this.FileName())
}

// RemoteTarget publishes complete sealed segments under SealedSegment's
// RemotePath. Publish must be idempotent: identical existing content succeeds,
// conflicting content is rejected, and partial content is never exposed under
// the final path. Retry and retention policies are owned by the coordinator.
type RemoteTarget interface {
	Publish(context.Context, SealedSegment) error
	io.Closer
}

func isNilRemoteValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
