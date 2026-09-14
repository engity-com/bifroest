package recording

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/audit"
)

const maximumEventElapsed = 10 * 365 * 24 * time.Hour

type CastWriter struct {
	output         io.Writer
	identity       *audit.Identity
	header         CastHeader
	metadata       CastMetadata
	digest         hash.Hash
	lastElapsed    time.Duration
	emittedElapsed time.Duration
	eventCount     uint64
	sealed         bool
	poisoned       error
}

func NewCastWriter(output io.Writer, identity *audit.Identity, header CastHeader, metadata CastMetadata) (*CastWriter, error) {
	if output == nil {
		return nil, fmt.Errorf("nil cast output")
	}
	if identity == nil || identity.PublicKey() == nil {
		return nil, fmt.Errorf("nil cast signing identity")
	}
	if err := validateCastHeader(header); err != nil {
		return nil, err
	}
	if err := validateCastMetadata(header, metadata); err != nil {
		return nil, err
	}
	if metadata.ProducerId != identity.ProducerId() {
		return nil, fmt.Errorf("recording producer ID does not match signing identity")
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(castContentHashDomain))
	result := &CastWriter{
		output:   output,
		identity: identity,
		header:   header,
		metadata: metadata,
		digest:   hasher,
	}
	if err := result.writeCanonicalContentLine(header); err != nil {
		return nil, err
	}
	if err := result.writeComment(castMetadataCommentPrefix, castMetadataWire{Schema: castMetadataSchema, CastMetadata: metadata}); err != nil {
		return nil, err
	}
	return result, nil
}

func (this *CastWriter) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	if err := this.validateOutputStream(stream); err != nil {
		return err
	}
	if err := this.validateElapsed(elapsed); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	for offset := 0; offset < len(data); {
		end := castOutputChunkEnd(data, offset)
		chunk := data[offset:end]
		if err := this.writeOutputEvent(elapsed, stream, chunk); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (this *CastWriter) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	if this == nil {
		return fmt.Errorf("nil cast writer")
	}
	if !this.metadata.Pty {
		return fmt.Errorf("cannot write a resize event for a non-PTY recording")
	}
	if columns == 0 || rows == 0 {
		return fmt.Errorf("terminal dimensions must be positive")
	}
	return this.writeEvent(elapsed, "r", fmt.Sprintf("%dx%d", columns, rows))
}

func (this *CastWriter) WriteMarker(elapsed time.Duration, label string) error {
	if !utf8.ValidString(label) {
		return fmt.Errorf("marker label is not valid UTF-8")
	}
	if len(label) > 4096 {
		return fmt.Errorf("marker label exceeds 4096 bytes")
	}
	return this.writeEvent(elapsed, "m", label)
}

func (this *CastWriter) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (CastDigest, error) {
	if this == nil {
		return CastDigest{}, fmt.Errorf("nil cast writer")
	}
	if this.poisoned != nil {
		return CastDigest{}, this.poisoned
	}
	if this.sealed {
		return CastDigest{}, fmt.Errorf("cast is already sealed")
	}
	if err := validateCastResult(this.metadata, result, exitStatus != nil); err != nil {
		return CastDigest{}, err
	}
	if err := this.validateElapsed(elapsed); err != nil {
		return CastDigest{}, err
	}
	if result.Status == CastStatusCompleted && !result.EndedAt.Equal(this.metadata.StartedAt.Add(elapsed)) {
		return CastDigest{}, fmt.Errorf("completed recording end time does not match its elapsed duration")
	}
	if exitStatus != nil {
		if err := this.writeEvent(elapsed, "x", fmt.Sprintf("%d", *exitStatus)); err != nil {
			return CastDigest{}, err
		}
	}
	if err := this.writeComment(castResultCommentPrefix, castResultWire{Schema: castResultSchema, CastResult: result}); err != nil {
		return CastDigest{}, err
	}

	var digest CastDigest
	copy(digest[:], this.digest.Sum(nil))
	signature, err := this.identity.NewSessionRecordingCastSignature(this.metadata.RecordingId.String(), digest.String())
	if err != nil {
		return CastDigest{}, this.poison(err)
	}
	payload, err := json.Marshal(signature)
	if err != nil {
		return CastDigest{}, this.poison(fmt.Errorf("cannot encode cast signature: %w", err))
	}
	if err := this.writeRawLine(append([]byte(castSignatureCommentPrefix), payload...)); err != nil {
		return CastDigest{}, err
	}
	this.sealed = true
	return digest, nil
}

func (this *CastWriter) writeOutputEvent(elapsed time.Duration, stream OutputStream, data []byte) error {
	valid := utf8.Valid(data)
	if stream == OutputStreamStderr || !valid {
		metadata := castEventMetadata{
			Schema:   castEventMetadataSchema,
			Sequence: this.eventCount + 1,
			Stream:   stream,
		}
		if !valid {
			metadata.Raw = append([]byte(nil), data...)
		}
		if err := this.writeComment(castEventCommentPrefix, metadata); err != nil {
			return err
		}
	}
	text := string(data)
	if !valid {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	return this.writeEvent(elapsed, "o", text)
}

func (this *CastWriter) writeEvent(elapsed time.Duration, code, data string) error {
	if err := this.validateElapsed(elapsed); err != nil {
		return err
	}
	rounded := (elapsed + time.Millisecond/2) / time.Millisecond * time.Millisecond
	interval := rounded - this.emittedElapsed
	encodedData := marshalCastEventString(data)
	seconds := interval / time.Second
	milliseconds := interval % time.Second / time.Millisecond
	line := fmt.Appendf(nil, "[%d.%03d,%q,%s]", seconds, milliseconds, code, encodedData)
	if err := this.writeContentLine(line); err != nil {
		return err
	}
	this.lastElapsed = elapsed
	this.emittedElapsed = rounded
	this.eventCount++
	return nil
}

func castOutputChunkEnd(data []byte, offset int) int {
	end := offset + MaximumOutputEventBytes
	if end >= len(data) {
		return len(data)
	}
	start := end
	for start > offset && !utf8.RuneStart(data[start]) {
		start--
	}
	if start == offset {
		return end
	}
	_, size := utf8.DecodeRune(data[start:])
	if size > 1 && start+size > end {
		return start
	}
	return end
}

func (this *CastWriter) writeComment(prefix string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return this.poison(fmt.Errorf("cannot encode cast comment: %w", err))
	}
	return this.writeContentLine(append([]byte(prefix), payload...))
}

func (this *CastWriter) writeCanonicalContentLine(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return this.poison(fmt.Errorf("cannot encode cast line: %w", err))
	}
	return this.writeContentLine(payload)
}

func (this *CastWriter) writeContentLine(line []byte) error {
	complete := append(append([]byte(nil), line...), '\n')
	if err := this.write(complete); err != nil {
		return err
	}
	_, _ = this.digest.Write(complete)
	return nil
}

func (this *CastWriter) writeRawLine(line []byte) error {
	return this.write(append(append([]byte(nil), line...), '\n'))
}

func (this *CastWriter) write(content []byte) error {
	written, err := this.output.Write(content)
	if err != nil {
		return this.poison(fmt.Errorf("cannot write cast: %w", err))
	}
	if written != len(content) {
		return this.poison(io.ErrShortWrite)
	}
	return nil
}

func (this *CastWriter) validateOutputStream(stream OutputStream) error {
	if this == nil {
		return fmt.Errorf("nil cast writer")
	}
	if this.metadata.Pty && stream != OutputStreamTerminal {
		return fmt.Errorf("PTY recordings require the terminal output stream")
	}
	if !this.metadata.Pty && stream != OutputStreamStdout && stream != OutputStreamStderr {
		return fmt.Errorf("non-PTY recordings require stdout or stderr")
	}
	return nil
}

func (this *CastWriter) validateElapsed(elapsed time.Duration) error {
	if this == nil {
		return fmt.Errorf("nil cast writer")
	}
	if this.poisoned != nil {
		return this.poisoned
	}
	if this.sealed {
		return fmt.Errorf("cast is already sealed")
	}
	if elapsed < this.lastElapsed {
		return fmt.Errorf("cast event time moved backwards")
	}
	if elapsed < 0 || elapsed > maximumEventElapsed {
		return fmt.Errorf("cast event time is outside the supported range")
	}
	return nil
}

func (this *CastWriter) poison(err error) error {
	if this != nil && this.poisoned == nil {
		this.poisoned = err
	}
	return err
}
