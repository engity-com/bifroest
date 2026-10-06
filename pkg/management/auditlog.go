package management

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

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

func RegisterAuditlogCommands(app *kingpin.Application, source ConfigurationSource, events AuditEventSource, ctx context.Context, output io.Writer, local bool) {
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
	var eventName, flowName, since, until string
	var withSensitive bool
	var limit int
	var identityFiles []string
	var eventAuditlog configuration.AuditlogName
	eventCmd := parent.Command("events", "Show verified audit events.")
	eventCmd.Flag("name", "Filter by event name.").StringVar(&eventName)
	eventCmd.Flag("flow", "Filter by flow (requires --with-sensitive).").StringVar(&flowName)
	eventCmd.Flag("since", "Events recorded at or after RFC3339 time.").StringVar(&since)
	eventCmd.Flag("until", "Events recorded at or before RFC3339 time.").StringVar(&until)
	eventCmd.Flag("limit", "Limit the number of newest matching events (0 = all).").Default("100").IntVar(&limit)
	eventCmd.Flag("with-sensitive", "Include private event fields (encrypted journals need a local decryption identity).").BoolVar(&withSensitive)
	if local {
		eventCmd.Flag("decryptionIdentityFile", "Local private key for encrypted events (repeatable).").StringsVar(&identityFiles)
	}
	eventCmd.Arg("name", "Name of the audit log.").Required().SetValue(&eventAuditlog)
	eventCmd.Action(func(*kingpin.ParseContext) error {
		filter := AuditEventFilter{Name: eventName, Flow: flowName, Limit: limit}
		var err error
		if since != "" {
			if filter.Since, err = time.Parse(time.RFC3339, since); err != nil {
				return fmt.Errorf("invalid --since: %w", err)
			}
		}
		if until != "" {
			if filter.Until, err = time.Parse(time.RFC3339, until); err != nil {
				return fmt.Errorf("invalid --until: %w", err)
			}
		}
		if flowName != "" && !withSensitive {
			return fmt.Errorf("--flow requires --with-sensitive")
		}
		records, err := events(ctx, path, eventAuditlog, withSensitive, identityFiles)
		if err != nil {
			return err
		}
		return WriteAuditEvents(output, Format(format), records, filter, withSensitive)
	})
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
