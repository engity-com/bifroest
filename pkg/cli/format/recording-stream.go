package format

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

// RecordingListStream writes each already verified entry immediately. Close is
// called only after successful completion; errors deliberately leave it partial.
type RecordingListStream struct {
	output  io.Writer
	format  Format
	count   uint64
	started bool
	closed  bool
	table   *tabwriter.Writer
}

type recordingStreamOutput struct{ io.Writer }

func (this recordingStreamOutput) Write(content []byte) (written int, err error) {
	written, err = this.Writer.Write(content)
	if err == nil && written != len(content) {
		err = io.ErrShortWrite
	}
	return written, err
}

func NewRecordingListStream(output io.Writer, selected Format) (*RecordingListStream, error) {
	if output == nil {
		return nil, fmt.Errorf("recording stream output is unavailable")
	}
	switch selected {
	case Text, Json, Yaml, Cbor, WireCborStream:
	default:
		return nil, fmt.Errorf("unsupported recording stream format %q", selected)
	}
	return &RecordingListStream{output: recordingStreamOutput{output}, format: selected}, nil
}

func writeRecordingStreamBytes(output io.Writer, content []byte) error {
	written, err := output.Write(content)
	if err == nil && written != len(content) {
		return io.ErrShortWrite
	}
	return err
}

func (this *RecordingListStream) start() error {
	if this.started {
		return nil
	}
	this.started = true
	switch this.format {
	case Text:
		this.table = tabwriter.NewWriter(this.output, 0, 0, 2, ' ', 0)
		return writeRow(this.table, []string{"ID", "AUDITLOG", "STATUS", "STARTED", "VERIFIED"})
	case Json:
		return writeRecordingStreamBytes(this.output, []byte("[\n"))
	case Cbor:
		return writeRecordingStreamBytes(this.output, []byte{0x9f})
	}
	return nil
}

func (this *RecordingListStream) Write(entry model.RecordingView) error {
	if this.closed {
		return io.ErrClosedPipe
	}
	if err := this.start(); err != nil {
		return err
	}
	var err error
	switch this.format {
	case Text:
		err = writeRow(this.table, []string{entry.ID, entry.Auditlog, entry.Status, entry.StartedAt.Format(time.RFC3339), entry.VerificationScope})
		if err == nil {
			err = this.table.Flush()
		}
	case Json:
		if this.count > 0 {
			if err := writeRecordingStreamBytes(this.output, []byte(",")); err != nil {
				return err
			}
		}
		var encoded []byte
		encoded, err = json.Marshal(entry)
		if err == nil {
			err = writeRecordingStreamBytes(this.output, append(encoded, '\n'))
		}
	case Yaml:
		var encoded []byte
		encoded, err = yaml.Marshal([]model.RecordingView{entry})
		if err == nil {
			err = writeRecordingStreamBytes(this.output, encoded)
		}
	case Cbor:
		var encoded []byte
		encoded, err = cbor.Marshal(entry)
		if err == nil {
			err = writeRecordingStreamBytes(this.output, encoded)
		}
	case WireCborStream:
		err = transport.WriteRecordingStreamEntry(this.output, entry)
	}
	if err == nil {
		this.count++
	}
	return err
}

func (this *RecordingListStream) Close() error {
	if this.closed {
		return io.ErrClosedPipe
	}
	this.closed = true
	if err := this.start(); err != nil {
		return err
	}
	switch this.format {
	case Text:
		return this.table.Flush()
	case Json:
		return writeRecordingStreamBytes(this.output, []byte("]\n"))
	case Yaml:
		if this.count == 0 {
			return writeRecordingStreamBytes(this.output, []byte("[]\n"))
		}
	case Cbor:
		return writeRecordingStreamBytes(this.output, []byte{0xff})
	case WireCborStream:
		return transport.WriteRecordingStreamEnd(this.output, this.count)
	}
	return nil
}
