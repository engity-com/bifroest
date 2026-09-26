package audit

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// Audit wire types are intentionally distinct from the recording wire types.
// Their shared codec and framing cannot grant them shared chain semantics.
type nativeAuditHeader struct {
	Version             uint8                  `cbor:"1,keyasint"`
	Encryption          uint8                  `cbor:"2,keyasint"`
	ProducerId          [32]byte               `cbor:"3,keyasint"`
	PublicKey           []byte                 `cbor:"4,keyasint"`
	Sequence            uint64                 `cbor:"5,keyasint"`
	PreviousSegmentHash [32]byte               `cbor:"6,keyasint"`
	PreviousRecordHash  [32]byte               `cbor:"7,keyasint"`
	CreatedAt           nativeformat.Timestamp `cbor:"8,keyasint"`
	Recipient           string                 `cbor:"9,keyasint,omitempty"`
	Signature           []byte                 `cbor:"10,keyasint"`
}

type nativeAuditPublicEvent struct {
	Name    string `cbor:"1,keyasint"`
	Domain  string `cbor:"2,keyasint,omitempty"`
	Outcome string `cbor:"3,keyasint,omitempty"`
}

type nativeAuditPrivateEvent struct {
	Flow                 string  `cbor:"1,keyasint,omitempty"`
	ConnectionId         string  `cbor:"2,keyasint,omitempty"`
	SessionId            string  `cbor:"3,keyasint,omitempty"`
	OperationId          string  `cbor:"4,keyasint,omitempty"`
	RecordingId          string  `cbor:"5,keyasint,omitempty"`
	RecordingDigest      string  `cbor:"6,keyasint,omitempty"`
	Target               string  `cbor:"7,keyasint,omitempty"`
	AuthenticationMethod string  `cbor:"8,keyasint,omitempty"`
	AuthenticationPhase  string  `cbor:"9,keyasint,omitempty"`
	AuthorizationKind    string  `cbor:"10,keyasint,omitempty"`
	SessionTask          string  `cbor:"11,keyasint,omitempty"`
	Reason               string  `cbor:"12,keyasint,omitempty"`
	ErrorCategory        string  `cbor:"13,keyasint,omitempty"`
	ExitCode             *int64  `cbor:"14,keyasint,omitempty"`
	BytesRead            *int64  `cbor:"15,keyasint,omitempty"`
	BytesWritten         *int64  `cbor:"16,keyasint,omitempty"`
	DurationMillis       *int64  `cbor:"17,keyasint,omitempty"`
	Count                *uint64 `cbor:"18,keyasint,omitempty"`
	Pty                  *bool   `cbor:"19,keyasint,omitempty"`
	AgentForwarding      *bool   `cbor:"20,keyasint,omitempty"`
	ForcedCommand        *bool   `cbor:"21,keyasint,omitempty"`
	SessionSubsystem     string  `cbor:"22,keyasint,omitempty"`
}

type nativeAuditRecord struct {
	Id                 [16]byte               `cbor:"1,keyasint"`
	RecordedAt         nativeformat.Timestamp `cbor:"2,keyasint"`
	PreviousRecordHash [32]byte               `cbor:"3,keyasint"`
	PublicEvent        nativeAuditPublicEvent `cbor:"4,keyasint"`
	PrivatePayload     []byte                 `cbor:"5,keyasint"`
	Signature          []byte                 `cbor:"6,keyasint"`
}

func (this nativeAuditRecord) ValidateNativeWire() error {
	if _, err := nativeformat.Marshal(this.PublicEvent, nativeformat.MaxMetadataPayload); err != nil {
		return fmt.Errorf("invalid public audit event: %w", err)
	}
	return nil
}

type nativeAuditSeal struct {
	Sequence       uint64                 `cbor:"1,keyasint"`
	RecordCount    uint64                 `cbor:"2,keyasint"`
	ContentBytes   uint64                 `cbor:"3,keyasint"`
	ContentHash    [32]byte               `cbor:"4,keyasint"`
	LastRecordHash [32]byte               `cbor:"5,keyasint"`
	SealedAt       nativeformat.Timestamp `cbor:"6,keyasint"`
	Signature      []byte                 `cbor:"7,keyasint"`
}
