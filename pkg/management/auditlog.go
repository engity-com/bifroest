package management

import (
	"fmt"
	"io"
	"sort"

	"github.com/alecthomas/kingpin/v2"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type AuditlogSummary struct {
	Name             configuration.AuditlogName `json:"name" yaml:"name"`
	Enabled          bool                       `json:"enabled" yaml:"enabled"`
	RecordingEnabled bool                       `json:"recordingEnabled" yaml:"recordingEnabled"`
	Encrypted        bool                       `json:"encrypted" yaml:"encrypted"`
}

func RegisterAuditlogCommands(app *kingpin.Application, source ConfigurationSource, output io.Writer, local bool) {
	parent := app.Command("auditlog", "Inspect configured audit logs.")
	var format, path string
	formats := []string{"table", "json", "yaml"}
	if !local {
		formats = append(formats, "cbor")
	}
	parent.Flag("format", "Display as a table/list, JSON, or YAML.").Default("table").EnumVar(&format, formats...)
	if local {
		parent.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&path)
	}
	parent.Command("ls", "List configured audit logs.").Action(func(*kingpin.ParseContext) error {
		conf, err := source(path)
		if err != nil {
			return err
		}
		return ListAuditlogs(output, Format(format), conf)
	})
	var name configuration.AuditlogName
	parent.Command("show", "Show audit-log settings.").Action(func(*kingpin.ParseContext) error {
		conf, err := source(path)
		if err != nil {
			return err
		}
		return ShowAuditlog(output, Format(format), conf, name)
	}).Arg("name", "Name of the audit log.").Required().SetValue(&name)
}

func ListAuditlogs(output io.Writer, format Format, conf *configuration.Configuration) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	entries := make([]AuditlogSummary, 0, len(conf.Auditlogs))
	for _, current := range conf.Auditlogs {
		entries = append(entries, AuditlogSummary{
			Name: current.Name, Enabled: current.Enabled, RecordingEnabled: current.Recording.Enabled,
			Encrypted: !current.EncryptionPublicKey.IsZero() || !current.EncryptionPublicKeyFile.IsZero(),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return WriteAuditlogList(output, format, entries)
}

func WriteAuditlogList(output io.Writer, format Format, entries []AuditlogSummary) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.Name.String(), fmt.Sprint(entry.Enabled), fmt.Sprint(entry.RecordingEnabled), fmt.Sprint(entry.Encrypted)})
	}
	return WriteList(output, format, []string{"NAME", "AUDIT", "RECORDING", "ENCRYPTED"}, rows, entries)
}

func ShowAuditlog(output io.Writer, format Format, conf *configuration.Configuration, name configuration.AuditlogName) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	for _, current := range conf.Auditlogs {
		if current.Name != name {
			continue
		}
		encoded, err := yaml.Marshal(current)
		if err != nil {
			return err
		}
		var settings map[string]any
		if err := yaml.Unmarshal(encoded, &settings); err != nil {
			return err
		}
		redactFlowSettings(settings)
		return WriteFlowSettings(output, format, settings)
	}
	return fmt.Errorf("auditlog %q does not exist", name)
}
