package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	NativeEventSetup uint8 = iota + 1
	NativeEventOutput
	NativeEventResize
	NativeEventMarker
	NativeEventPaddingCheckpoint
	NativeEventResult
)

// NativeCastEvent is one complete CBOR event, not a Cast line. Elapsed is an
// absolute nanosecond duration. Output is already split into <=64 KiB events.
type NativeCastEvent struct {
	Kind       uint8
	Header     CastHeader
	Metadata   CastMetadata
	Elapsed    time.Duration
	Stream     OutputStream
	Data       []byte
	Columns    uint32
	Rows       uint32
	Label      string
	Result     CastResult
	ExitStatus *uint32
}

func nativeStreamNumber(stream OutputStream) uint8 {
	switch stream {
	case OutputStreamTerminal:
		return 1
	case OutputStreamStdout:
		return 2
	case OutputStreamStderr:
		return 3
	}
	return 0
}

func nativeStreamName(value uint64) OutputStream {
	switch value {
	case 1:
		return OutputStreamTerminal
	case 2:
		return OutputStreamStdout
	case 3:
		return OutputStreamStderr
	}
	return ""
}

func nativeStatusNumber(status CastStatus) uint8 {
	switch status {
	case CastStatusCompleted:
		return 1
	case CastStatusFailed:
		return 2
	case CastStatusIncomplete:
		return 3
	}
	return 0
}

// EncodeNativeRecordingEvents emits only deterministic integer-key CBOR maps.
// Cross-chunk ordering and exact Cast semantics are checked by the renderer.
func EncodeNativeRecordingEvents(events []NativeCastEvent) ([]byte, error) {
	if len(events) == 0 || len(events) > 4096 {
		return nil, fmt.Errorf("invalid native recording event count")
	}
	encoded := make([]any, 0, len(events))
	for _, event := range events {
		m := map[uint64]any{1: event.Kind}
		switch event.Kind {
		case NativeEventSetup:
			h := event.Header
			meta := event.Metadata
			if err := validateCastHeader(h); err != nil {
				return nil, err
			}
			if err := validateCastMetadata(h, meta); err != nil {
				return nil, err
			}
			hm := map[uint64]any{1: h.Version, 2: h.Terminal.Columns, 3: h.Terminal.Rows, 5: h.Timestamp}
			if h.Terminal.Type != "" {
				hm[4] = h.Terminal.Type
			}
			mm := map[uint64]any{1: [16]byte(meta.RecordingId), 2: [16]byte(meta.ConnectionId), 3: [16]byte(meta.SessionId), 4: [16]byte(meta.OperationId), 5: string(meta.Flow), 6: string(meta.Task), 7: meta.Pty, 8: [32]byte(meta.ProducerId), 9: nativeformat.TimestampOf(meta.StartedAt)}
			m[2], m[3] = hm, mm
		case NativeEventOutput, NativeEventResize, NativeEventMarker, NativeEventResult:
			if event.Elapsed < 0 || event.Elapsed > maximumEventElapsed {
				return nil, fmt.Errorf("invalid native event elapsed time")
			}
			m[2] = uint64(event.Elapsed)
			switch event.Kind {
			case NativeEventOutput:
				if len(event.Data) == 0 || len(event.Data) > MaximumOutputEventBytes || nativeStreamNumber(event.Stream) == 0 {
					return nil, fmt.Errorf("invalid native output event")
				}
				m[3], m[4] = nativeStreamNumber(event.Stream), event.Data
			case NativeEventResize:
				if event.Columns == 0 || event.Rows == 0 || event.Columns > MaximumCastTerminalDimension || event.Rows > MaximumCastTerminalDimension {
					return nil, fmt.Errorf("invalid native resize event")
				}
				m[3], m[4] = event.Columns, event.Rows
			case NativeEventMarker:
				if len(event.Label) > 4096 || !utf8.ValidString(event.Label) {
					return nil, fmt.Errorf("invalid native marker event")
				}
				m[3] = event.Label
			case NativeEventResult:
				if nativeStatusNumber(event.Result.Status) == 0 || len(event.Result.Reason) > 255 || !utf8.ValidString(event.Result.Reason) || (event.ExitStatus != nil && *event.ExitStatus > MaximumCastExitStatus) {
					return nil, fmt.Errorf("invalid native result event")
				}
				r := map[uint64]any{1: nativeStatusNumber(event.Result.Status), 2: nativeformat.TimestampOf(event.Result.EndedAt)}
				if event.Result.Reason != "" {
					r[3] = event.Result.Reason
				}
				m[3] = r
				if event.ExitStatus != nil {
					m[4] = *event.ExitStatus
				}
			}
		case NativeEventPaddingCheckpoint:
		default:
			return nil, fmt.Errorf("unknown native event type %d", event.Kind)
		}
		encoded = append(encoded, m)
	}
	payload, err := nativeformat.Marshal(map[uint64]any{1: uint8(1), 2: encoded}, nativeformat.MaxRecordingDecodedChunk)
	if err != nil {
		return nil, err
	}
	if _, err := decodeNativeRecordingEvents(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func nativeMap(value any, required, optional []uint64) (map[any]any, error) {
	m, ok := value.(map[any]any)
	if !ok || len(m) < len(required) || len(m) > len(required)+len(optional) {
		return nil, fmt.Errorf("invalid native event map")
	}
	for _, key := range required {
		if _, exists := m[key]; !exists {
			return nil, fmt.Errorf("missing native event key %d", key)
		}
	}
	for key := range m {
		found := false
		for _, valid := range append(append([]uint64(nil), required...), optional...) {
			found = found || key == valid
		}
		if !found {
			return nil, fmt.Errorf("unknown native event key %v", key)
		}
	}
	return m, nil
}

func nativeUnsigned(value any) (uint64, error) {
	n, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("native event value is not unsigned integer")
	}
	return n, nil
}

func nativeString(value any) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("native event value is not text")
	}
	return s, nil
}

func nativeBytes(value any, length int) ([]byte, error) {
	b, ok := value.([]byte)
	if !ok || len(b) != length {
		return nil, fmt.Errorf("native event has invalid byte string length")
	}
	return b, nil
}

func nativeTimestamp(value any) (time.Time, error) {
	parts, ok := value.([]any)
	if !ok || len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid native event timestamp")
	}
	var seconds int64
	switch n := parts[0].(type) {
	case int64:
		seconds = n
	case uint64:
		if n > math.MaxInt64 {
			return time.Time{}, fmt.Errorf("native timestamp overflows seconds")
		}
		seconds = int64(n)
	default:
		return time.Time{}, fmt.Errorf("invalid native timestamp seconds")
	}
	nanos, err := nativeUnsigned(parts[1])
	if err != nil || nanos >= 1e9 {
		return time.Time{}, fmt.Errorf("invalid native timestamp nanoseconds")
	}
	return time.Unix(seconds, int64(nanos)).UTC(), nil
}

func decodeNativeRecordingEvents(payload []byte) ([]NativeCastEvent, error) {
	root, err := nativeformat.Unmarshal[map[uint64]any](payload, nativeformat.MaxRecordingDecodedChunk)
	if err != nil {
		return nil, err
	}
	if len(root) != 2 {
		return nil, fmt.Errorf("invalid native event group keys")
	}
	version, err := nativeUnsigned(root[1])
	if err != nil || version != 1 {
		return nil, fmt.Errorf("unsupported native event version")
	}
	items, ok := root[2].([]any)
	if !ok || len(items) == 0 || len(items) > 4096 {
		return nil, fmt.Errorf("invalid native event group")
	}
	events := make([]NativeCastEvent, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[any]any)
		if !ok {
			return nil, fmt.Errorf("native event must be a map")
		}
		kind, err := nativeUnsigned(m[uint64(1)])
		if err != nil || kind < 1 || kind > 6 {
			return nil, fmt.Errorf("invalid native event kind")
		}
		e := NativeCastEvent{Kind: uint8(kind)}
		switch e.Kind {
		case NativeEventSetup:
			if _, err = nativeMap(m, []uint64{1, 2, 3}, nil); err != nil {
				return nil, err
			}
			h, err := nativeMap(m[uint64(2)], []uint64{1, 2, 3, 5}, []uint64{4})
			if err != nil {
				return nil, err
			}
			version, e1 := nativeUnsigned(h[uint64(1)])
			cols, e2 := nativeUnsigned(h[uint64(2)])
			rows, e3 := nativeUnsigned(h[uint64(3)])
			stamp, e4 := nativeUnsigned(h[uint64(5)])
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || version > math.MaxInt || cols > math.MaxUint32 || rows > math.MaxUint32 || stamp > math.MaxInt64 {
				return nil, fmt.Errorf("invalid native cast header values")
			}
			e.Header = CastHeader{Version: int(version), Terminal: CastTerminal{Columns: uint32(cols), Rows: uint32(rows)}, Timestamp: int64(stamp)}
			if value, exists := h[uint64(4)]; exists {
				e.Header.Terminal.Type, err = nativeString(value)
				if err != nil || e.Header.Terminal.Type == "" {
					return nil, fmt.Errorf("invalid native terminal type")
				}
			}
			meta, err := nativeMap(m[uint64(3)], []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, nil)
			if err != nil {
				return nil, err
			}
			id, e1 := nativeBytes(meta[uint64(1)], 16)
			connectionID, e2 := nativeBytes(meta[uint64(2)], 16)
			sessionID, e3 := nativeBytes(meta[uint64(3)], 16)
			operationID, e4 := nativeBytes(meta[uint64(4)], 16)
			flow, e5 := nativeString(meta[uint64(5)])
			task, e6 := nativeString(meta[uint64(6)])
			pty, e7 := meta[uint64(7)].(bool)
			producer, e8 := nativeBytes(meta[uint64(8)], 32)
			started, e9 := nativeTimestamp(meta[uint64(9)])
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || !e7 || e8 != nil || e9 != nil {
				return nil, fmt.Errorf("invalid native cast metadata")
			}
			e.Metadata = CastMetadata{RecordingId: Id(*(*[16]byte)(id)), ConnectionId: connection.Id(*(*[16]byte)(connectionID)), SessionId: session.Id(*(*[16]byte)(sessionID)), OperationId: uuid.UUID(*(*[16]byte)(operationID)), Flow: configuration.FlowName(flow), Task: audit.SessionTask(task), Pty: pty, ProducerId: audit.ProducerId(*(*[32]byte)(producer)), StartedAt: started}
		case NativeEventPaddingCheckpoint:
			if _, err = nativeMap(m, []uint64{1}, nil); err != nil {
				return nil, err
			}
		default:
			required := []uint64{1, 2, 3}
			optional := []uint64(nil)
			if e.Kind == NativeEventOutput || e.Kind == NativeEventResize {
				required = append(required, 4)
			}
			if e.Kind == NativeEventResult {
				optional = []uint64{4}
			}
			if _, err = nativeMap(m, required, optional); err != nil {
				return nil, err
			}
			nanos, err := nativeUnsigned(m[uint64(2)])
			if err != nil || nanos > uint64(maximumEventElapsed) {
				return nil, fmt.Errorf("native event elapsed time is invalid")
			}
			e.Elapsed = time.Duration(nanos)
			switch e.Kind {
			case NativeEventOutput:
				stream, err := nativeUnsigned(m[uint64(3)])
				if err != nil {
					return nil, err
				}
				e.Stream = nativeStreamName(stream)
				data, ok := m[uint64(4)].([]byte)
				if e.Stream == "" || !ok || len(data) == 0 || len(data) > MaximumOutputEventBytes {
					return nil, fmt.Errorf("invalid native output event")
				}
				e.Data = data
			case NativeEventResize:
				cols, e1 := nativeUnsigned(m[uint64(3)])
				rows, e2 := nativeUnsigned(m[uint64(4)])
				if e1 != nil || e2 != nil || cols > math.MaxUint32 || rows > math.MaxUint32 {
					return nil, fmt.Errorf("invalid native resize")
				}
				e.Columns, e.Rows = uint32(cols), uint32(rows)
			case NativeEventMarker:
				e.Label, err = nativeString(m[uint64(3)])
				if err != nil {
					return nil, err
				}
			case NativeEventResult:
				r, err := nativeMap(m[uint64(3)], []uint64{1, 2}, []uint64{3})
				if err != nil {
					return nil, err
				}
				status, err := nativeUnsigned(r[uint64(1)])
				if err != nil || status < 1 || status > 3 {
					return nil, fmt.Errorf("invalid native result status")
				}
				e.Result.Status, _ = castStatusFromNativeRecording(uint8(status))
				e.Result.EndedAt, err = nativeTimestamp(r[uint64(2)])
				if err != nil {
					return nil, err
				}
				if reason, exists := r[uint64(3)]; exists {
					e.Result.Reason, err = nativeString(reason)
					if err != nil || e.Result.Reason == "" {
						return nil, fmt.Errorf("invalid native result reason")
					}
				}
				if exit, exists := m[uint64(4)]; exists {
					status, err := nativeUnsigned(exit)
					if err != nil || status > uint64(MaximumCastExitStatus) {
						return nil, fmt.Errorf("invalid native exit status")
					}
					value := uint32(status)
					e.ExitStatus = &value
				}
			}
		}
		events = append(events, e)
	}
	return events, nil
}

type nativeCastBuffer struct {
	bytes.Buffer
	maximum int64
}

func (b *nativeCastBuffer) Write(data []byte) (int, error) {
	if int64(len(data)) > b.maximum-int64(b.Len()) {
		return 0, fmt.Errorf("native Cast exceeds %d bytes", b.maximum)
	}
	return b.Buffer.Write(data)
}

type nativeCastCountWriter struct {
	output  io.Writer
	maximum uint64
	bytes   uint64
}

func (w *nativeCastCountWriter) Write(data []byte) (int, error) {
	if uint64(len(data)) > w.maximum-w.bytes {
		return 0, fmt.Errorf("native Cast exceeds %d bytes", w.maximum)
	}
	n, err := w.output.Write(data)
	if n < 0 || n > len(data) {
		return 0, io.ErrShortWrite
	}
	w.bytes += uint64(n)
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

type nativeCastRenderer struct {
	header   NativeRecordingHeader
	seal     NativeRecordingSeal
	output   *nativeCastCountWriter
	writer   *CastWriter
	groups   uint64
	finished bool
}

func newNativeCastRenderer(output io.Writer, header NativeRecordingHeader, seal NativeRecordingSeal, maximumCastBytes int64) (*nativeCastRenderer, error) {
	if output == nil || header.Version != 1 || maximumCastBytes <= 0 || maximumCastBytes > DefaultMaximumCastBytes || seal.CastBytes > uint64(maximumCastBytes) {
		return nil, fmt.Errorf("invalid native Cast renderer output or limit")
	}
	if err := validateNativeRecordingSeal(seal, header); err != nil {
		return nil, err
	}
	return &nativeCastRenderer{header: header, seal: seal, output: &nativeCastCountWriter{output: output, maximum: uint64(maximumCastBytes)}}, nil
}

func (r *nativeCastRenderer) consumeGroup(events []NativeCastEvent) error {
	r.groups++
	if r.groups > r.seal.ChunkCount {
		return fmt.Errorf("native Cast has more event groups than its seal")
	}
	for i, event := range events {
		if (event.Kind == NativeEventPaddingCheckpoint) != (r.groups < r.seal.ChunkCount && i == len(events)-1) {
			return fmt.Errorf("native recording group has invalid padding checkpoint")
		}
	}
	for _, event := range events {
		if r.finished {
			return fmt.Errorf("native recording event follows result")
		}
		if r.writer == nil && event.Kind != NativeEventSetup {
			return fmt.Errorf("native recording has no initial setup")
		}
		var err error
		switch event.Kind {
		case NativeEventSetup:
			if r.writer != nil || event.Metadata.RecordingId != Id(r.header.RecordingId) || event.Metadata.ProducerId != audit.ProducerId(r.header.ProducerId) || nativeformat.TimestampOf(event.Metadata.StartedAt) != r.header.StartedAt {
				return fmt.Errorf("native setup does not match its signed header")
			}
			if err := validateCastHeader(event.Header); err != nil {
				return err
			}
			if err := validateCastMetadata(event.Header, event.Metadata); err != nil {
				return err
			}
			r.writer = &CastWriter{output: r.output, header: event.Header, metadata: event.Metadata, digest: sha256.New()}
			_, _ = r.writer.digest.Write([]byte(castContentHashDomain))
			if err := r.writer.writeCanonicalContentLine(event.Header); err != nil {
				return err
			}
			err = r.writer.writeComment(castMetadataCommentPrefix, castMetadataWire{Schema: castMetadataSchema, CastMetadata: event.Metadata})
		case NativeEventOutput:
			err = r.writer.WriteOutput(event.Elapsed, event.Stream, event.Data)
		case NativeEventResize:
			err = r.writer.WriteResize(event.Elapsed, event.Columns, event.Rows)
		case NativeEventMarker:
			err = r.writer.WriteMarker(event.Elapsed, event.Label)
		case NativeEventPaddingCheckpoint:
			_, err = padCastForSha256Checkpoint(r.writer)
		case NativeEventResult:
			status, statusErr := castStatusFromNativeRecording(r.seal.Status)
			if statusErr != nil || status != event.Result.Status || nativeformat.TimestampOf(event.Result.EndedAt) != r.seal.EndedAt {
				return fmt.Errorf("native result does not match signed seal")
			}
			var digest CastDigest
			digest, err = r.writer.sealContent(event.Elapsed, event.Result, event.ExitStatus)
			if err == nil {
				if digest != CastDigest(r.seal.CastDigest) {
					return fmt.Errorf("native Cast digest does not match signed seal")
				}
				signature := audit.SessionRecordingCastSignature{Schema: audit.SessionRecordingCastSignatureSchema, RecordingId: Id(r.header.RecordingId).String(), ProducerId: audit.ProducerId(r.header.ProducerId), Digest: digest.String(), PublicKey: r.header.PublicKey, Signature: r.seal.CastSignature}
				if _, err = audit.VerifySessionRecordingCastSignature(signature); err == nil {
					var payload []byte
					payload, err = json.Marshal(signature)
					if err == nil {
						err = r.writer.writeRawLine(append([]byte(castSignatureCommentPrefix), payload...))
					}
				}
			}
			r.finished = true
		default:
			return fmt.Errorf("unsupported native event kind %d", event.Kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *nativeCastRenderer) finish() error {
	if !r.finished || r.groups != r.seal.ChunkCount || r.output.bytes != r.seal.CastBytes {
		return fmt.Errorf("native Cast result, event groups or byte count differs from seal")
	}
	return nil
}

// RenderNativeRecordingCast reconstructs and fully verifies the signed Cast
// before returning any bytes. The caller must first verify the outer container
// and supply its authenticated header/seal and independently decoded groups.
func RenderNativeRecordingCast(groups [][]byte, header NativeRecordingHeader, seal NativeRecordingSeal, maximumCastBytes int64) ([]byte, error) {
	if len(groups) == 0 || uint64(len(groups)) > DefaultMaximumNativeRecordingChunks || uint64(len(groups)) != seal.ChunkCount {
		return nil, fmt.Errorf("invalid native Cast limits or event groups")
	}
	output := &nativeCastBuffer{maximum: maximumCastBytes}
	renderer, err := newNativeCastRenderer(output, header, seal, maximumCastBytes)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		events, err := decodeNativeRecordingEvents(group)
		if err != nil {
			return nil, err
		}
		if err := renderer.consumeGroup(events); err != nil {
			return nil, err
		}
	}
	if err := renderer.finish(); err != nil {
		return nil, err
	}
	verification, err := VerifyCast(bytes.NewReader(output.Bytes()), CastVerifyOptions{MaximumBytes: maximumCastBytes, ExpectedProducerId: audit.ProducerId(header.ProducerId)})
	if err != nil || verification == nil || verification.Digest != CastDigest(seal.CastDigest) {
		return nil, fmt.Errorf("reconstructed native Cast failed full verification: %v", err)
	}
	return bytes.Clone(output.Bytes()), nil
}
