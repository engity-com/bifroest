package evidence

import (
	"bytes"
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// AuditByteSnapshot owns a fixed byte inventory, not synthetic filesystem state.
// It makes no claim about original paths, inodes, links or OS provenance. Native
// sources implement the capability with their additional real file proofs.
type AuditByteSnapshot struct {
	head      []byte
	published []AuditPublishedSegment
	active    *AuditActiveSegment
	next      int
	exhausted bool
	closed    bool
}

func NewAuditByteSnapshot(head []byte, published []AuditPublishedSegment, active *AuditActiveSegment) (*AuditByteSnapshot, error) {
	if len(head) == 0 || len(head) > nativeformat.MaxMetadataPayload {
		return nil, fmt.Errorf("invalid native audit snapshot head size")
	}
	var sequence uint64
	for _, entry := range published {
		if entry.Sequence == 0 || entry.Sequence <= sequence || entry.Image == nil {
			return nil, fmt.Errorf("audit byte inventory must be ordered and contain immutable images")
		}
		sequence = entry.Sequence
	}
	result := &AuditByteSnapshot{head: bytes.Clone(head), published: append([]AuditPublishedSegment(nil), published...)}
	if active != nil {
		if active.Image == nil {
			return nil, fmt.Errorf("audit byte active entry has no immutable image")
		}
		copy := *active
		if copy.AliasOfPublished != 0 {
			if len(published) == 0 || copy.AliasOfPublished != sequence || HashAuditSegment(copy.Image.data) != published[len(published)-1].Hash {
				return nil, fmt.Errorf("audit byte active alias must equal the last published image")
			}
		}
		result.active = &copy
	}
	return result, nil
}

func (this *AuditByteSnapshot) available(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if this == nil || this.closed {
		return fmt.Errorf("audit byte snapshot is closed or missing")
	}
	return nil
}

func (this *AuditByteSnapshot) Head(ctx context.Context) ([]byte, error) {
	if err := this.available(ctx); err != nil {
		return nil, err
	}
	return bytes.Clone(this.head), nil
}

func (this *AuditByteSnapshot) NextPublished(ctx context.Context) (AuditPublishedSegment, bool, error) {
	if err := this.available(ctx); err != nil {
		return AuditPublishedSegment{}, false, err
	}
	if this.next == len(this.published) {
		this.exhausted = true
		return AuditPublishedSegment{}, false, nil
	}
	entry := this.published[this.next]
	this.next++
	return entry, true, nil
}

func (this *AuditByteSnapshot) Active(ctx context.Context) (AuditActiveSegment, bool, error) {
	if err := this.available(ctx); err != nil {
		return AuditActiveSegment{}, false, err
	}
	if !this.exhausted {
		return AuditActiveSegment{}, false, fmt.Errorf("audit byte inventory has not been exhausted")
	}
	if this.active == nil {
		return AuditActiveSegment{}, false, nil
	}
	return *this.active, true, nil
}

func (this *AuditByteSnapshot) Revalidate(ctx context.Context) error {
	if err := this.available(ctx); err != nil {
		return err
	}
	if !this.exhausted {
		return fmt.Errorf("audit byte inventory has not been exhausted")
	}
	// The owned descriptor list, head and private image storage cannot be
	// changed through this capability. This is not an OS tree revalidation.
	return nil
}

func (this *AuditByteSnapshot) Close() error {
	if this == nil || this.closed {
		return nil
	}
	this.closed = true
	this.head, this.published, this.active = nil, nil, nil
	return nil
}
