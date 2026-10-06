package management

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
	// FormatCBOR is used only inside the versioned SSH management exchange.
	FormatCBOR Format = "cbor"
)

const MaxWireResultBytes = 16 << 20

type wireResult struct {
	Version uint8           `cbor:"1,keyasint"`
	Payload cbor.RawMessage `cbor:"2,keyasint"`
}

func DecodeWireResult(input io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(input, MaxWireResultBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxWireResultBytes {
		return fmt.Errorf("management response exceeds %d bytes", MaxWireResultBytes)
	}
	var frame wireResult
	if err := cbor.Unmarshal(data, &frame); err != nil {
		return err
	}
	if frame.Version != 1 || len(frame.Payload) == 0 {
		return fmt.Errorf("unsupported or empty management response")
	}
	mode, err := (cbor.DecOptions{DefaultMapType: reflect.TypeFor[map[string]any](), DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(frame.Payload, target)
}

type Field struct {
	Name  string
	Value string
}

func WriteList(output io.Writer, format Format, columns []string, rows [][]string, structured any) error {
	if format != FormatTable {
		return writeStructured(output, format, structured)
	}
	if len(columns) == 0 {
		return fmt.Errorf("a table must contain columns")
	}
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	if err := writeRow(writer, columns); err != nil {
		return err
	}
	for _, row := range rows {
		if len(row) != len(columns) {
			return fmt.Errorf("table row has %d values instead of %d", len(row), len(columns))
		}
		if err := writeRow(writer, row); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func WriteDetail(output io.Writer, format Format, fields []Field, structured any) error {
	if format != FormatTable {
		return writeStructured(output, format, structured)
	}
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	for _, field := range fields {
		if err := writeRow(writer, []string{field.Name + ":", field.Value}); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writeRow(output io.Writer, cells []string) error {
	for index, cell := range cells {
		if index != 0 {
			if _, err := io.WriteString(output, "\t"); err != nil {
				return err
			}
		}
		cell = strings.Map(func(r rune) rune {
			if r < ' ' || r == 127 {
				return ' '
			}
			return r
		}, cell)
		if _, err := io.WriteString(output, cell); err != nil {
			return err
		}
	}
	_, err := io.WriteString(output, "\n")
	return err
}

func writeStructured(output io.Writer, format Format, value any) error {
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(value)
	case FormatYAML:
		return yaml.NewEncoder(output).Encode(value)
	case FormatCBOR:
		payload, err := cbor.Marshal(value)
		if err != nil {
			return err
		}
		encoded, err := cbor.Marshal(wireResult{Version: 1, Payload: payload})
		if err != nil {
			return err
		}
		if len(encoded) > MaxWireResultBytes {
			return fmt.Errorf("management response exceeds %d bytes", MaxWireResultBytes)
		}
		written, err := output.Write(encoded)
		if err == nil && written != len(encoded) {
			return io.ErrShortWrite
		}
		return err
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}
