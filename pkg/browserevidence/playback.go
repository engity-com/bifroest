package browserevidence

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

const MaximumPlaybackEvents = 100_000
const MaximumPlaybackColumns = 512
const MaximumPlaybackRows = 256
const MaximumPlaybackCells = 32_768

// The local rendering wire contains fixed 13-byte frame headers, followed by
// output bytes or two little-endian uint32 dimensions. Times are microseconds.
// This is a bounded renderer transport, not a Cast decoder or evidence schema.
const PlaybackFrameHeaderBytes = 13

type PlaybackMetadata struct {
	Version     int             `json:"version"`
	RecordingID string          `json:"recordingId"`
	Producer    string          `json:"producer"`
	Trust       string          `json:"trust"`
	Columns     uint32          `json:"columns"`
	Rows        uint32          `json:"rows"`
	Pty         bool            `json:"pty"`
	Frames      uint32          `json:"frames"`
	DurationUs  int64           `json:"durationUs"`
	Status      cast.CastStatus `json:"status"`
	ExitStatus  *uint32         `json:"exitStatus"`
}

type Playback struct {
	Metadata PlaybackMetadata
	Frames   []byte
}

func playbackDimensions(columns, rows uint32) bool {
	return columns > 0 && columns <= MaximumPlaybackColumns && rows > 0 && rows <= MaximumPlaybackRows && uint64(columns)*uint64(rows) <= MaximumPlaybackCells
}

// PreparePlayback verifies the exact owned immutable local Cast again with the
// caller's independent producer expectation. No provisional event data escapes.
// It neither reclaims source/outer/decryption evidence nor opens keys or URLs.
func PreparePlayback(ctx context.Context, source []byte, id, producer string, allowUntrusted bool) (result *Playback, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if err := ctx.Err(); err != nil {
			if result != nil {
				clear(result.Frames)
			}
			result, resultErr = nil, err
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !protocol.ValidID(id) {
		return nil, ErrInput
	}
	if len(source) == 0 || int64(len(source)) > MaximumInputBytes {
		return nil, ErrLimit
	}
	var expected evidence.ProducerId
	if producer != "" {
		if expected.UnmarshalText([]byte(producer)) != nil || expected.IsZero() || expected.String() != producer {
			return nil, ErrInput
		}
	} else if !allowUntrusted {
		return nil, ErrInput
	}
	image := bytes.Clone(source)
	defer clear(image)
	var frames boundedOutput
	defer func() { clear(frames.Bytes()) }()
	var count, frameCount uint32
	var elapsed int64
	verified, err := cast.InspectCastEvents(bytes.NewReader(image), cast.CastVerifyOptions{Context: ctx, MaximumBytes: MaximumInputBytes, ExpectedProducerId: expected, AllowUntrusted: allowUntrusted}, func(event cast.CastEvent) error {
		defer clear(event.Data)
		count++
		if count > MaximumPlaybackEvents {
			return ErrLimit
		}
		elapsed = event.Elapsed.Microseconds()
		var kind byte
		var payload []byte
		switch event.Code {
		case "o":
			switch event.Stream {
			case cast.OutputStreamTerminal:
				kind = 0
			case cast.OutputStreamStdout:
				kind = 1
			case cast.OutputStreamStderr:
				kind = 2
			default:
				return ErrVerification
			}
			payload = event.Data
		case "r":
			if !playbackDimensions(event.Columns, event.Rows) {
				return ErrLimit
			}
			kind = 3
			payload = make([]byte, 8)
			binary.LittleEndian.PutUint32(payload, event.Columns)
			binary.LittleEndian.PutUint32(payload[4:], event.Rows)
		default:
			return nil // Markers/exit/unknown codes preserve timing, never execute.
		}
		var header [PlaybackFrameHeaderBytes]byte
		binary.LittleEndian.PutUint64(header[:8], uint64(elapsed))
		header[8] = kind
		binary.LittleEndian.PutUint32(header[9:], uint32(len(payload)))
		if _, err := frames.Write(header[:]); err != nil {
			return err
		}
		if _, err := frames.Write(payload); err != nil {
			return err
		}
		frameCount++
		return nil
	})
	if err != nil {
		return nil, verificationError(err)
	}
	if verified.Metadata.RecordingId.String() != id {
		return nil, ErrVerification
	}
	if !playbackDimensions(verified.Header.Terminal.Columns, verified.Header.Terminal.Rows) {
		return nil, ErrLimit
	}
	trust := "untrusted"
	if verified.Trusted {
		trust = "pinned"
	}
	return &Playback{Metadata: PlaybackMetadata{Version: 1, RecordingID: id, Producer: verified.Metadata.ProducerId.String(), Trust: trust, Columns: verified.Header.Terminal.Columns, Rows: verified.Header.Terminal.Rows, Pty: verified.Metadata.Pty, Frames: frameCount, DurationUs: elapsed, Status: verified.Result.Status, ExitStatus: verified.ExitStatus}, Frames: bytes.Clone(frames.Bytes())}, nil
}
