package recording

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

type CastVerifyOptions struct {
	Context            context.Context
	MaximumBytes       int64
	ExpectedProducerId audit.ProducerId
	AllowUntrusted     bool
}

type CastVerification struct {
	Header       CastHeader
	Metadata     CastMetadata
	Result       CastResult
	ExitStatus   *uint32
	EventCount   uint64
	OutputEvents uint64
	ResizeEvents uint64
	MarkerEvents uint64
	Digest       CastDigest
	Fingerprint  string
	Trusted      bool
}

func VerifyCast(input io.Reader, options CastVerifyOptions) (*CastVerification, error) {
	if input == nil {
		return nil, errors.System.Newf("nil cast input")
	}
	if options.ExpectedProducerId == (audit.ProducerId{}) && !options.AllowUntrusted {
		return nil, errors.Config.Newf("expected producer ID is required unless untrusted verification is explicitly allowed")
	}
	maximumBytes := options.MaximumBytes
	if maximumBytes == 0 {
		maximumBytes = DefaultMaximumCastBytes
	}
	if maximumBytes < 1 {
		return nil, errors.Config.Newf("maximum cast size must be positive")
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	reader := bufio.NewReaderSize(input, 64<<10)
	total := int64(0)
	lineNumber := 0
	readLine := func() ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, errors.System.Newf("cast verification canceled: %w", err)
		}
		line, err := readCastLine(reader, &total, maximumBytes)
		if err == nil {
			lineNumber++
		}
		return line, err
	}

	headerLine, err := readLine()
	if err != nil {
		return nil, errors.System.Newf("cannot read cast header: %w", err)
	}
	var header CastHeader
	if err := decodeCastHeader(headerLine, &header); err != nil {
		return nil, errors.System.Newf("illegal cast header: %w", err)
	}

	metadataLine, err := readLine()
	if err != nil {
		return nil, errors.System.Newf("cannot read cast metadata: %w", err)
	}
	metadataPayload, ok := bytes.CutPrefix(metadataLine, []byte(castMetadataCommentPrefix))
	if !ok {
		return nil, errors.System.Newf("cast metadata is not the second line")
	}
	var metadataWire castMetadataWire
	if err := decodeCanonicalCastJSON(metadataPayload, &metadataWire); err != nil {
		return nil, errors.System.Newf("illegal cast metadata: %w", err)
	}
	if metadataWire.Schema != castMetadataSchema {
		return nil, errors.System.Newf("unsupported cast metadata schema %q", metadataWire.Schema)
	}
	if err := validateCastMetadata(header, metadataWire.CastMetadata); err != nil {
		return nil, errors.System.Newf("illegal cast metadata: %w", err)
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(castContentHashDomain))
	_, _ = hasher.Write(append(append([]byte(nil), headerLine...), '\n'))
	_, _ = hasher.Write(append(append([]byte(nil), metadataLine...), '\n'))
	verification := &CastVerification{Header: header, Metadata: metadataWire.CastMetadata}
	var pending *castEventMetadata
	var resultSeen bool
	var exitSeen bool
	var elapsed time.Duration

	for {
		line, readErr := readLine()
		if readErr == io.EOF {
			return nil, errors.System.Newf("cast has no final signature")
		}
		if readErr != nil {
			return nil, errors.System.Newf("cannot read cast line %d: %w", lineNumber+1, readErr)
		}
		if signaturePayload, signature := bytes.CutPrefix(line, []byte(castSignatureCommentPrefix)); signature {
			if pending != nil {
				return nil, errors.System.Newf("cast event metadata has no corresponding event")
			}
			if !resultSeen {
				return nil, errors.System.Newf("cast signature precedes its result")
			}
			if err := verifyCastSignature(signaturePayload, verification, hasher, options.ExpectedProducerId); err != nil {
				return nil, err
			}
			if _, err := readLine(); err != io.EOF {
				if err == nil {
					return nil, errors.System.Newf("cast contains data after its final signature")
				}
				return nil, errors.System.Newf("cannot check data after cast signature: %w", err)
			}
			return verification, nil
		}
		if resultSeen {
			return nil, errors.System.Newf("cast contains data between its result and signature")
		}
		if eventPayload, eventComment := bytes.CutPrefix(line, []byte(castEventCommentPrefix)); eventComment {
			if pending != nil {
				return nil, errors.System.Newf("cast contains consecutive event metadata comments")
			}
			var value castEventMetadata
			if err := decodeCanonicalCastJSON(eventPayload, &value); err != nil {
				return nil, errors.System.Newf("illegal cast event metadata: %w", err)
			}
			if err := validateCastEventMetadata(value, verification.Metadata, verification.EventCount+1); err != nil {
				return nil, err
			}
			pending = &value
		} else if resultPayload, resultComment := bytes.CutPrefix(line, []byte(castResultCommentPrefix)); resultComment {
			if pending != nil {
				return nil, errors.System.Newf("cast event metadata has no corresponding event")
			}
			var value castResultWire
			if err := decodeCanonicalCastJSON(resultPayload, &value); err != nil {
				return nil, errors.System.Newf("illegal cast result: %w", err)
			}
			if value.Schema != castResultSchema {
				return nil, errors.System.Newf("unsupported cast result schema %q", value.Schema)
			}
			if err := validateCastResult(verification.Metadata, value.CastResult, exitSeen); err != nil {
				return nil, errors.System.Newf("illegal cast result: %w", err)
			}
			if value.Status == CastStatusCompleted {
				difference := value.EndedAt.Sub(verification.Metadata.StartedAt) - elapsed
				if difference < -time.Millisecond/2 || difference > time.Millisecond/2 {
					return nil, errors.System.Newf("completed recording duration does not match its event intervals")
				}
			}
			verification.Result = value.CastResult
			resultSeen = true
		} else if bytes.HasPrefix(line, []byte("# bifroest:")) {
			return nil, errors.System.Newf("unsupported or misplaced Bifroest cast comment")
		} else if len(line) > 0 && line[0] == '#' {
			if pending != nil {
				return nil, errors.System.Newf("cast event metadata is not followed by an event")
			}
		} else {
			if exitSeen {
				return nil, errors.System.Newf("cast contains an event after its exit status")
			}
			interval, code, data, err := decodeCastEvent(line)
			if err != nil {
				return nil, errors.System.Newf("illegal cast event on line %d: %w", lineNumber, err)
			}
			if interval > maximumEventElapsed-elapsed {
				return nil, errors.System.Newf("cast event duration exceeds the supported range")
			}
			elapsed += interval
			verification.EventCount++
			switch code {
			case "o":
				if err := validateCastOutputEvent(data, pending); err != nil {
					return nil, err
				}
				verification.OutputEvents++
			case "i":
				return nil, errors.System.Newf("bifroest cast contains a forbidden input event")
			case "m":
				if pending != nil {
					return nil, errors.System.Newf("cast event metadata does not describe an output event")
				}
				if len(data) > 4096 {
					return nil, errors.System.Newf("cast marker exceeds 4096 bytes")
				}
				verification.MarkerEvents++
			case "r":
				if pending != nil {
					return nil, errors.System.Newf("cast event metadata does not describe an output event")
				}
				if !verification.Metadata.Pty {
					return nil, errors.System.Newf("non-PTY cast contains a resize event")
				}
				if err := validateResizeEvent(data); err != nil {
					return nil, err
				}
				verification.ResizeEvents++
			case "x":
				if pending != nil {
					return nil, errors.System.Newf("cast event metadata does not describe an output event")
				}
				status, err := parseExitStatus(data)
				if err != nil {
					return nil, err
				}
				verification.ExitStatus = &status
				exitSeen = true
			default:
				if pending != nil {
					return nil, errors.System.Newf("cast event metadata does not describe an output event")
				}
			}
			pending = nil
		}
		_, _ = hasher.Write(append(append([]byte(nil), line...), '\n'))
	}
}

func verifyCastSignature(payload []byte, verification *CastVerification, hasher hash.Hash, expected audit.ProducerId) error {
	var wire audit.SessionRecordingCastSignature
	if err := decodeCanonicalCastJSON(payload, &wire); err != nil {
		return errors.System.Newf("illegal cast signature metadata: %w", err)
	}
	if wire.RecordingId != verification.Metadata.RecordingId.String() || wire.ProducerId != verification.Metadata.ProducerId {
		return errors.System.Newf("cast signature identity does not match its metadata")
	}
	var digest CastDigest
	copy(digest[:], hasher.Sum(nil))
	if wire.Digest != digest.String() {
		return errors.System.Newf("cast content digest does not match its signature")
	}
	if expected != (audit.ProducerId{}) && wire.ProducerId != expected {
		return errors.System.Newf("cast belongs to producer %s instead of %s", wire.ProducerId, expected)
	}
	publicKey, err := audit.VerifySessionRecordingCastSignature(wire)
	if err != nil {
		return err
	}
	verification.Digest = digest
	verification.Fingerprint = ssh.FingerprintSHA256(publicKey.ToSsh())
	verification.Trusted = expected != (audit.ProducerId{})
	return nil
}

func decodeCastHeader(payload []byte, target *CastHeader) error {
	if err := validateJSONLine(payload); err != nil {
		return err
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		return err
	}
	if object == nil {
		return errors.System.Newf("header is not an object")
	}
	version, exists := object["version"]
	if !exists {
		return errors.System.Newf("header has no version")
	}
	terminal, exists := object["term"]
	if !exists {
		return errors.System.Newf("header has no terminal metadata")
	}
	timestamp, exists := object["timestamp"]
	if !exists {
		return errors.System.Newf("header has no timestamp")
	}
	var terminalObject map[string]json.RawMessage
	if err := json.Unmarshal(terminal, &terminalObject); err != nil || terminalObject == nil {
		return errors.System.Newf("terminal metadata is not an object")
	}
	columns, exists := terminalObject["cols"]
	if !exists {
		return errors.System.Newf("terminal metadata has no columns")
	}
	rows, exists := terminalObject["rows"]
	if !exists {
		return errors.System.Newf("terminal metadata has no rows")
	}
	if err := json.Unmarshal(version, &target.Version); err != nil {
		return errors.System.Newf("header version is not an integer")
	}
	if err := json.Unmarshal(columns, &target.Terminal.Columns); err != nil {
		return errors.System.Newf("terminal columns are not an integer")
	}
	if err := json.Unmarshal(rows, &target.Terminal.Rows); err != nil {
		return errors.System.Newf("terminal rows are not an integer")
	}
	if terminalType, exists := terminalObject["type"]; exists {
		if err := json.Unmarshal(terminalType, &target.Terminal.Type); err != nil {
			return errors.System.Newf("terminal type is not a string")
		}
	}
	if err := json.Unmarshal(timestamp, &target.Timestamp); err != nil {
		return errors.System.Newf("header timestamp is not an integer")
	}
	return validateCastHeader(*target)
}

func decodeCastEvent(payload []byte) (time.Duration, string, string, error) {
	if err := validateJSONLine(payload); err != nil {
		return 0, "", "", err
	}
	var values []json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil {
		return 0, "", "", err
	}
	if len(values) != 3 {
		return 0, "", "", errors.System.Newf("event must contain exactly three values")
	}
	var rawInterval json.Number
	decoder := json.NewDecoder(bytes.NewReader(values[0]))
	decoder.UseNumber()
	if err := decoder.Decode(&rawInterval); err != nil {
		return 0, "", "", errors.System.Newf("event interval is not a number")
	}
	interval, err := strconv.ParseFloat(rawInterval.String(), 64)
	if err != nil || math.IsInf(interval, 0) || math.IsNaN(interval) || interval < 0 || interval > maximumEventElapsed.Seconds() {
		return 0, "", "", errors.System.Newf("event interval is illegal")
	}
	var code, data string
	if err := json.Unmarshal(values[1], &code); err != nil || len(code) != 1 {
		return 0, "", "", errors.System.Newf("event code is illegal")
	}
	if err := json.Unmarshal(values[2], &data); err != nil {
		return 0, "", "", errors.System.Newf("event data is not a string")
	}
	if err := rejectLiteralCastControlCharacters(values[2]); err != nil {
		return 0, "", "", err
	}
	return time.Duration(math.Round(interval * float64(time.Second))), code, data, nil
}

func validateCastEventMetadata(value castEventMetadata, metadata CastMetadata, sequence uint64) error {
	if value.Schema != castEventMetadataSchema {
		return errors.System.Newf("unsupported cast event metadata schema %q", value.Schema)
	}
	if value.Sequence != sequence {
		return errors.System.Newf("cast event metadata sequence is %d instead of %d", value.Sequence, sequence)
	}
	if metadata.Pty && value.Stream != OutputStreamTerminal {
		return errors.System.Newf("PTY cast event metadata does not identify terminal output")
	}
	if !metadata.Pty && value.Stream != OutputStreamStdout && value.Stream != OutputStreamStderr {
		return errors.System.Newf("non-PTY cast event metadata has an illegal stream")
	}
	if len(value.Raw) > MaximumOutputEventBytes {
		return errors.System.Newf("raw cast event exceeds %d bytes", MaximumOutputEventBytes)
	}
	if len(value.Raw) == 0 && value.Stream != OutputStreamStderr {
		return errors.System.Newf("redundant cast event metadata")
	}
	if len(value.Raw) > 0 && utf8.Valid(value.Raw) {
		return errors.System.Newf("raw cast event contains valid UTF-8")
	}
	return nil
}

func validateCastOutputEvent(data string, eventMetadata *castEventMetadata) error {
	if eventMetadata == nil {
		if len(data) > MaximumOutputEventBytes {
			return errors.System.Newf("cast output event exceeds %d bytes", MaximumOutputEventBytes)
		}
		return nil
	}
	if len(eventMetadata.Raw) > 0 && strings.ToValidUTF8(string(eventMetadata.Raw), "\uFFFD") != data {
		return errors.System.Newf("raw cast event does not match its playback representation")
	}
	if len(eventMetadata.Raw) == 0 && len(data) > MaximumOutputEventBytes {
		return errors.System.Newf("cast output event exceeds %d bytes", MaximumOutputEventBytes)
	}
	return nil
}

func validateResizeEvent(data string) error {
	columnsText, rowsText, ok := strings.Cut(data, "x")
	if !ok {
		return errors.System.Newf("illegal resize event %q", data)
	}
	columns, columnsErr := strconv.ParseUint(columnsText, 10, 32)
	rows, rowsErr := strconv.ParseUint(rowsText, 10, 32)
	if columnsErr != nil || rowsErr != nil || columns == 0 || rows == 0 || fmt.Sprintf("%dx%d", columns, rows) != data {
		return errors.System.Newf("illegal resize event %q", data)
	}
	return nil
}

func decodeCanonicalCastJSON(payload []byte, target any) error {
	if err := validateJSONLine(payload); err != nil {
		return err
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, canonical) {
		return errors.System.Newf("JSON is not canonically encoded")
	}
	return nil
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	return ensureJSONEnd(decoder)
}

func rejectLiteralCastControlCharacters(value []byte) error {
	for offset := 1; offset < len(value)-1; {
		if value[offset] == '\\' {
			if value[offset+1] == 'u' {
				offset += 6
			} else {
				offset += 2
			}
			continue
		}
		character, size := utf8.DecodeRune(value[offset:])
		if mustEscapeCastCodePoint(character) {
			return errors.System.Newf("event data contains an unescaped control character")
		}
		offset += size
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.System.Newf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.System.Newf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.System.Newf("object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.System.Newf("array is not terminated")
		}
	default:
		return errors.System.Newf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.System.Newf("contains a second JSON value")
		}
		return errors.System.Newf("contains trailing data: %w", err)
	}
	return nil
}

func validateJSONLine(payload []byte) error {
	if len(payload) == 0 {
		return errors.System.Newf("empty line")
	}
	if !utf8.Valid(payload) {
		return errors.System.Newf("line is not valid UTF-8")
	}
	if bytes.IndexByte(payload, '\r') >= 0 || bytes.IndexByte(payload, '\n') >= 0 {
		return errors.System.Newf("line contains an embedded line ending")
	}
	return rejectUnpairedJSONSurrogates(payload)
}

func rejectUnpairedJSONSurrogates(payload []byte) error {
	inString := false
	for offset := 0; offset < len(payload); {
		switch payload[offset] {
		case '"':
			inString = !inString
			offset++
		case '\\':
			if !inString || offset+1 >= len(payload) {
				offset++
				continue
			}
			if payload[offset+1] != 'u' {
				offset += 2
				continue
			}
			value, ok := decodeJSONUnicodeEscape(payload[offset:])
			if !ok {
				return errors.System.Newf("line contains an illegal Unicode escape")
			}
			if value >= 0xd800 && value <= 0xdbff {
				if offset+12 > len(payload) || payload[offset+6] != '\\' || payload[offset+7] != 'u' {
					return errors.System.Newf("line contains an unpaired high surrogate")
				}
				low, validLow := decodeJSONUnicodeEscape(payload[offset+6:])
				if !validLow || low < 0xdc00 || low > 0xdfff {
					return errors.System.Newf("line contains an unpaired high surrogate")
				}
				offset += 12
				continue
			}
			if value >= 0xdc00 && value <= 0xdfff {
				return errors.System.Newf("line contains an unpaired low surrogate")
			}
			offset += 6
		default:
			offset++
		}
	}
	return nil
}

func decodeJSONUnicodeEscape(value []byte) (uint16, bool) {
	if len(value) < 6 || value[0] != '\\' || value[1] != 'u' {
		return 0, false
	}
	var decoded uint16
	for _, character := range value[2:6] {
		decoded <<= 4
		switch {
		case character >= '0' && character <= '9':
			decoded |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			decoded |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			decoded |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return decoded, true
}

func readCastLine(reader *bufio.Reader, total *int64, maximumBytes int64) ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		fragment, err := reader.ReadSlice('\n')
		*total += int64(len(fragment))
		if *total > maximumBytes {
			return nil, errors.System.Newf("cast exceeds %d bytes", maximumBytes)
		}
		if len(line)+len(fragment) > MaximumCastLineBytes+1 {
			return nil, errors.System.Newf("cast line exceeds %d bytes", MaximumCastLineBytes)
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(line) == 0 {
				return nil, io.EOF
			}
			return nil, errors.System.Newf("cast line is not terminated by LF")
		}
		if err != nil {
			return nil, err
		}
		if len(line) == 1 {
			return nil, errors.System.Newf("cast contains an empty line")
		}
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			return nil, errors.System.Newf("cast uses CRLF instead of LF")
		}
		return line, nil
	}
}
