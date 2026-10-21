package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/recording"
)

const WireRecordingListStreamCommand = "_bifroest-management-recording-list-stream-v1"
const maximumRecordingStreamFrameBytes = 64 << 10

const (
	recordingStreamEntry uint8 = iota + 1
	recordingStreamEnd
	recordingStreamError
)

type recordingStreamFrame struct {
	Version uint8           `cbor:"1,keyasint"`
	Kind    uint8           `cbor:"2,keyasint"`
	Payload cbor.RawMessage `cbor:"3,keyasint"`
}

func writeRecordingStreamFrame(output io.Writer, kind uint8, value any) error {
	payload, err := cbor.Marshal(value)
	if err != nil {
		return err
	}
	encoded, err := cbor.Marshal(recordingStreamFrame{Version: 1, Kind: kind, Payload: payload})
	if err != nil {
		return err
	}
	if len(encoded) > maximumRecordingStreamFrameBytes {
		return fmt.Errorf("recording stream frame exceeds %d bytes", maximumRecordingStreamFrameBytes)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err := io.Copy(output, bytes.NewReader(length[:])); err != nil {
		return err
	}
	_, err = io.Copy(output, bytes.NewReader(encoded))
	return err
}

func WriteRecordingStreamEntry(output io.Writer, entry model.RecordingView) error {
	return writeRecordingStreamFrame(output, recordingStreamEntry, entry)
}

func WriteRecordingStreamEnd(output io.Writer, count uint64) error {
	return writeRecordingStreamFrame(output, recordingStreamEnd, count)
}

func WriteRecordingStreamError(output io.Writer, err error) error {
	return writeRecordingStreamFrame(output, recordingStreamError, err.Error())
}

// DecodeRecordingListStream yields bounded individual entries and requires an
// explicit, count-checked end frame followed by EOF. A partial stream is an error.
func DecodeRecordingListStream(input io.Reader, consume func(model.RecordingView) error) error {
	mode, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return err
	}
	var count uint64
	for {
		var length [4]byte
		if _, err := io.ReadFull(input, length[:]); err != nil {
			return fmt.Errorf("recording stream ended before its completion frame: %w", err)
		}
		size := binary.BigEndian.Uint32(length[:])
		if size == 0 || size > maximumRecordingStreamFrameBytes {
			return fmt.Errorf("invalid recording stream frame length %d", size)
		}
		encoded := make([]byte, int(size))
		if _, err := io.ReadFull(input, encoded); err != nil {
			return fmt.Errorf("incomplete recording stream frame: %w", err)
		}
		var frame recordingStreamFrame
		if err := mode.Unmarshal(encoded, &frame); err != nil {
			return err
		}
		if frame.Version != 1 || len(frame.Payload) == 0 {
			return fmt.Errorf("unsupported or empty recording stream frame")
		}
		switch frame.Kind {
		case recordingStreamEntry:
			if count >= uint64(recording.MaximumSealedPageSize) {
				return fmt.Errorf("recording stream exceeds the maximum page size")
			}
			var entry model.RecordingView
			if err := mode.Unmarshal(frame.Payload, &entry); err != nil {
				return err
			}
			if err := consume(entry); err != nil {
				return err
			}
			count++
		case recordingStreamEnd:
			var expected uint64
			if err := mode.Unmarshal(frame.Payload, &expected); err != nil {
				return err
			}
			if expected != count {
				return fmt.Errorf("recording stream completion count does not match its entries")
			}
			var trailing [1]byte
			if _, err := io.ReadFull(input, trailing[:]); err != io.EOF {
				return fmt.Errorf("recording stream has trailing data or failed after completion: %v", err)
			}
			return nil
		case recordingStreamError:
			var message string
			if err := mode.Unmarshal(frame.Payload, &message); err != nil {
				return err
			}
			return fmt.Errorf("remote recording stream failed: %s", message)
		default:
			return fmt.Errorf("unknown recording stream frame kind %d", frame.Kind)
		}
	}
}
