package management

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

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
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}
