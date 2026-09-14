package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	castVersion                = 3
	castMetadataSchema         = "bifroest.asciicast-metadata/v1"
	castEventMetadataSchema    = "bifroest.asciicast-event/v1"
	castResultSchema           = "bifroest.asciicast-result/v1"
	castContentHashDomain      = "BIFROEST-ASCIICAST-CONTENT-HASH/v1\x00"
	castMetadataCommentPrefix  = "# bifroest:metadata:v1 "
	castEventCommentPrefix     = "# bifroest:event:v1 "
	castResultCommentPrefix    = "# bifroest:result:v1 "
	castSignatureCommentPrefix = "# bifroest:signature:v1 "

	MaximumCastLineBytes    = 1 << 20
	MaximumOutputEventBytes = 64 << 10
	DefaultMaximumCastBytes = int64(16 << 30)
)

type CastTerminal struct {
	Columns uint32 `json:"cols"`
	Rows    uint32 `json:"rows"`
	Type    string `json:"type,omitempty"`
}

type CastHeader struct {
	Version   int          `json:"version"`
	Terminal  CastTerminal `json:"term"`
	Timestamp int64        `json:"timestamp"`
}

type CastMetadata struct {
	RecordingId  Id                     `json:"recordingId"`
	ConnectionId connection.Id          `json:"connectionId"`
	SessionId    session.Id             `json:"sessionId"`
	OperationId  uuid.UUID              `json:"operationId"`
	Flow         configuration.FlowName `json:"flow"`
	Task         audit.SessionTask      `json:"task"`
	Pty          bool                   `json:"pty"`
	ProducerId   audit.ProducerId       `json:"producerId"`
	StartedAt    time.Time              `json:"startedAt"`
}

type CastStatus string

const (
	CastStatusCompleted  CastStatus = "completed"
	CastStatusFailed     CastStatus = "failed"
	CastStatusIncomplete CastStatus = "incomplete"
)

type CastResult struct {
	Status  CastStatus `json:"status"`
	EndedAt time.Time  `json:"endedAt"`
	Reason  string     `json:"reason,omitempty"`
}

type OutputStream string

const (
	OutputStreamTerminal OutputStream = "terminal"
	OutputStreamStdout   OutputStream = "stdout"
	OutputStreamStderr   OutputStream = "stderr"
)

type castMetadataWire struct {
	Schema string `json:"schema"`
	CastMetadata
}

type castEventMetadata struct {
	Schema   string       `json:"schema"`
	Sequence uint64       `json:"sequence"`
	Stream   OutputStream `json:"stream"`
	Raw      []byte       `json:"raw,omitempty"`
}

type castResultWire struct {
	Schema string `json:"schema"`
	CastResult
}

type CastDigest [sha256.Size]byte

func (this CastDigest) String() string {
	return hex.EncodeToString(this[:])
}

func (this CastDigest) IsZero() bool {
	return this == CastDigest{}
}

func (this CastDigest) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *CastDigest) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return fmt.Errorf("illegal cast digest length: %d", len(text))
	}
	var decoded CastDigest
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return fmt.Errorf("illegal cast digest: %w", err)
	}
	if decoded.String() != string(text) {
		return fmt.Errorf("cast digest is not canonical")
	}
	*this = decoded
	return nil
}

func validateCastHeader(header CastHeader) error {
	if header.Version != castVersion {
		return fmt.Errorf("unsupported asciicast version %d", header.Version)
	}
	if header.Terminal.Columns == 0 || header.Terminal.Rows == 0 {
		return fmt.Errorf("terminal dimensions must be positive")
	}
	if len(header.Terminal.Type) > 255 {
		return fmt.Errorf("terminal type exceeds 255 bytes")
	}
	if !utf8.ValidString(header.Terminal.Type) {
		return fmt.Errorf("terminal type is not valid UTF-8")
	}
	for _, character := range header.Terminal.Type {
		if mustEscapeCastCodePoint(character) {
			return fmt.Errorf("terminal type contains a control character")
		}
	}
	if header.Timestamp <= 0 {
		return fmt.Errorf("cast timestamp must be positive")
	}
	return nil
}

func validateCastMetadata(header CastHeader, metadata CastMetadata) error {
	if err := validateId(metadata.RecordingId); err != nil {
		return err
	}
	if metadata.ConnectionId.IsZero() {
		return fmt.Errorf("connection ID is empty")
	}
	if metadata.SessionId.IsZero() {
		return fmt.Errorf("session ID is empty")
	}
	if metadata.OperationId == uuid.Nil || metadata.OperationId.Version() != 4 || metadata.OperationId.Variant() != uuid.RFC4122 {
		return fmt.Errorf("illegal operation ID %q", metadata.OperationId)
	}
	if err := metadata.Flow.Validate(); err != nil {
		return fmt.Errorf("illegal recording flow: %w", err)
	}
	if metadata.Task != audit.SessionTaskShell && metadata.Task != audit.SessionTaskExec {
		return fmt.Errorf("illegal recording task %q", metadata.Task)
	}
	if metadata.ProducerId.IsZero() {
		return fmt.Errorf("recording producer ID is empty")
	}
	if metadata.StartedAt.IsZero() || metadata.StartedAt.Location() != time.UTC {
		return fmt.Errorf("recording start time must be UTC")
	}
	if metadata.StartedAt.Unix() != header.Timestamp {
		return fmt.Errorf("recording start time does not match cast timestamp")
	}
	return nil
}

func validateCastResult(metadata CastMetadata, result CastResult, hasExitStatus bool) error {
	switch result.Status {
	case CastStatusCompleted:
		if !hasExitStatus {
			return fmt.Errorf("completed recording has no exit status")
		}
	case CastStatusFailed, CastStatusIncomplete:
	default:
		return fmt.Errorf("illegal recording status %q", result.Status)
	}
	if result.EndedAt.IsZero() || result.EndedAt.Location() != time.UTC {
		return fmt.Errorf("recording end time must be UTC")
	}
	if result.EndedAt.Before(metadata.StartedAt) {
		return fmt.Errorf("recording end time precedes its start")
	}
	if result.EndedAt.Sub(metadata.StartedAt) > maximumEventElapsed {
		return fmt.Errorf("recording duration exceeds the supported range")
	}
	if len(result.Reason) > 255 {
		return fmt.Errorf("recording result reason exceeds 255 bytes")
	}
	if !utf8.ValidString(result.Reason) {
		return fmt.Errorf("recording result reason is not valid UTF-8")
	}
	for _, character := range result.Reason {
		if mustEscapeCastCodePoint(character) {
			return fmt.Errorf("recording result reason contains a control character")
		}
	}
	return nil
}

func parseExitStatus(value string) (uint32, error) {
	status, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(status, 10) != value {
		return 0, fmt.Errorf("illegal exit status %q", value)
	}
	return uint32(status), nil
}
