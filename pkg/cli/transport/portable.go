package transport

import (
	"io"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

// Compatibility adapters retain the native CLI/SSH API. The actual encoders and
// decoders live in the portable wire package, not a second browser implementation.
const (
	WireCommand                    = wire.WireCommand
	WireRecordingCommand           = wire.WireRecordingCommand
	WireRecordingListStreamCommand = wire.WireRecordingListStreamCommand
	MaxWireResultBytes             = wire.MaxWireResultBytes
)

type WireRequest = wire.WireRequest
type RecordingArtifactHeader = wire.RecordingArtifactHeader

func EncodeWireRequest(args []string) ([]byte, error)     { return wire.EncodeWireRequest(args) }
func DecodeWireRequest(input io.Reader) ([]string, error) { return wire.DecodeWireRequest(input) }
func EncodeWireResult(value any) ([]byte, error)          { return wire.EncodeWireResult(value) }
func DecodeWireResult(input io.Reader, target any) error  { return wire.DecodeWireResult(input, target) }
func WriteRecordingArtifact(output io.Writer, header RecordingArtifactHeader, content io.Reader) error {
	return wire.WriteRecordingArtifact(output, header, content)
}
func ReadRecordingArtifact(input io.Reader, output io.Writer, maxBytes int64) (RecordingArtifactHeader, error) {
	return wire.ReadRecordingArtifact(input, output, maxBytes)
}
func WriteRecordingStreamEntry(output io.Writer, entry model.RecordingView) error {
	return wire.WriteRecordingStreamEntry(output, entry)
}
func WriteRecordingStreamEnd(output io.Writer, count uint64) error {
	return wire.WriteRecordingStreamEnd(output, count)
}
func WriteRecordingStreamError(output io.Writer, err error) error {
	return wire.WriteRecordingStreamError(output, err)
}
func DecodeRecordingListStream(input io.Reader, consume func(model.RecordingView) error) error {
	return wire.DecodeRecordingListStream(input, consume)
}
