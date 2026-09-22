package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	CastVersion                = 3
	castVersion                = CastVersion
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

	MaximumCastTerminalDimension = uint32(1<<16 - 1)
	MaximumCastExitStatus        = uint32(1<<31 - 1)
)

type recordingWriterLimits struct {
	maximumContainerBytes uint64
	maximumCastBytes      uint64
	maximumChunks         uint64
}

func newRecordingWriterLimits(maximumContainerBytes, maximumCastBytes int64, maximumChunks uint64, defaultMaximumContainerBytes int64, defaultMaximumChunks uint64) (recordingWriterLimits, error) {
	if maximumContainerBytes == 0 {
		maximumContainerBytes = defaultMaximumContainerBytes
	}
	if maximumContainerBytes < 1 {
		return recordingWriterLimits{}, errors.Config.Newf("maximum Recording container size must be positive")
	}
	maximumCastBytes = effectiveMaximumCastBytes(maximumCastBytes)
	if maximumCastBytes < 1 {
		return recordingWriterLimits{}, errors.Config.Newf("maximum Cast size must be positive")
	}
	if maximumChunks == 0 {
		maximumChunks = defaultMaximumChunks
	}
	return recordingWriterLimits{
		maximumContainerBytes: uint64(maximumContainerBytes),
		maximumCastBytes:      uint64(maximumCastBytes),
		maximumChunks:         maximumChunks,
	}, nil
}

func recordingCountExceedsLimit(current, increment, reserve, maximum uint64) bool {
	return current > maximum || increment > maximum-current || reserve > maximum-current-increment
}

type CastTerminal struct {
	Columns uint32 `json:"cols"`
	Rows    uint32 `json:"rows"`
	Type    string `json:"type,omitempty"`
}

func (this CastTerminal) Validate() error {
	if this.Columns == 0 || this.Rows == 0 {
		return errors.System.Newf("terminal dimensions must be positive")
	}
	if this.Columns > MaximumCastTerminalDimension || this.Rows > MaximumCastTerminalDimension {
		return errors.System.Newf("terminal dimensions exceed %d", MaximumCastTerminalDimension)
	}
	if len(this.Type) > 255 {
		return errors.System.Newf("terminal type exceeds 255 bytes")
	}
	if !utf8.ValidString(this.Type) {
		return errors.System.Newf("terminal type is not valid UTF-8")
	}
	for _, character := range this.Type {
		if mustEscapeCastCodePoint(character) {
			return errors.System.Newf("terminal type contains a control character")
		}
	}
	return nil
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
		return errors.Config.Newf("illegal cast digest length: %d", len(text))
	}
	var decoded CastDigest
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal cast digest: %w", err)
	}
	if decoded.String() != string(text) {
		return errors.Config.Newf("cast digest is not canonical")
	}
	*this = decoded
	return nil
}

func validateCastHeader(header CastHeader) error {
	if header.Version != CastVersion {
		return errors.System.Newf("unsupported asciicast version %d", header.Version)
	}
	if err := header.Terminal.Validate(); err != nil {
		return err
	}
	if header.Timestamp <= 0 {
		return errors.System.Newf("cast timestamp must be positive")
	}
	return nil
}

func validateCastMetadata(header CastHeader, metadata CastMetadata) error {
	if err := validateId(metadata.RecordingId); err != nil {
		return err
	}
	if metadata.ConnectionId.IsZero() {
		return errors.System.Newf("connection ID is empty")
	}
	if metadata.SessionId.IsZero() {
		return errors.System.Newf("session ID is empty")
	}
	if metadata.OperationId == uuid.Nil || metadata.OperationId.Version() != 4 || metadata.OperationId.Variant() != uuid.RFC4122 {
		return errors.System.Newf("illegal operation ID %q", metadata.OperationId)
	}
	if err := metadata.Flow.Validate(); err != nil {
		return errors.System.Newf("illegal recording flow: %w", err)
	}
	if metadata.Task != audit.SessionTaskShell && metadata.Task != audit.SessionTaskExec {
		return errors.System.Newf("illegal recording task %q", metadata.Task)
	}
	if metadata.ProducerId.IsZero() {
		return errors.System.Newf("recording producer ID is empty")
	}
	if metadata.StartedAt.IsZero() || metadata.StartedAt.Location() != time.UTC {
		return errors.System.Newf("recording start time must be UTC")
	}
	if metadata.StartedAt.Unix() != header.Timestamp {
		return errors.System.Newf("recording start time does not match cast timestamp")
	}
	return nil
}

func validateCastResult(metadata CastMetadata, result CastResult, hasExitStatus bool) error {
	switch result.Status {
	case CastStatusCompleted:
		if !hasExitStatus {
			return errors.System.Newf("completed recording has no exit status")
		}
	case CastStatusFailed, CastStatusIncomplete:
	default:
		return errors.System.Newf("illegal recording status %q", result.Status)
	}
	if result.EndedAt.IsZero() || result.EndedAt.Location() != time.UTC {
		return errors.System.Newf("recording end time must be UTC")
	}
	if result.EndedAt.Before(metadata.StartedAt) {
		return errors.System.Newf("recording end time precedes its start")
	}
	if result.EndedAt.Sub(metadata.StartedAt) > maximumEventElapsed {
		return errors.System.Newf("recording duration exceeds the supported range")
	}
	if len(result.Reason) > 255 {
		return errors.System.Newf("recording result reason exceeds 255 bytes")
	}
	if !utf8.ValidString(result.Reason) {
		return errors.System.Newf("recording result reason is not valid UTF-8")
	}
	for _, character := range result.Reason {
		if mustEscapeCastCodePoint(character) {
			return errors.System.Newf("recording result reason contains a control character")
		}
	}
	return nil
}

func parseExitStatus(value string) (uint32, error) {
	status, err := strconv.ParseUint(value, 10, 31)
	if err != nil || strconv.FormatUint(status, 10) != value {
		return 0, errors.System.Newf("illegal exit status %q", value)
	}
	return uint32(status), nil
}
