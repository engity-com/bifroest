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

type AuditEventsOptions struct {
	Format            string
	ConfigurationPath string
	EventName         string
	FlowName          string
	Since             string
	Until             string
	Auditlog          configuration.AuditlogName
	Limit             int
	WithSensitive     bool
	IdentityFiles     []string
}

func RegisterAuditlogCommands(app *kingpin.Application, source ConfigurationSource, events AuditEventSource, ctx context.Context, output io.Writer, local bool) (*kingpin.CmdClause, *AuditEventsOptions) {
	parent := app.Command("auditlog", "Inspect configured audit logs.")
	opts := &AuditEventsOptions{}
	var path string
	formats := []string{"table", "json", "yaml"}
	if !local {
		formats = append(formats, "cbor")
	}
	parent.Flag("format", "Display as a table/list, JSON, or YAML.").Default("table").EnumVar(&opts.Format, formats...)
	list := parent.Command("ls", "List configured audit logs.")
	if local {
		list.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&path)
	}
	list.Action(func(*kingpin.ParseContext) error {
		conf, err := source(path)
		if err != nil {
			return err
		}
		return ListAuditlogs(output, Format(opts.Format), conf)
	})
	var name configuration.AuditlogName
	show := parent.Command("show", "Show audit-log settings.")
	if local {
		show.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&path)
	}
	show.Action(func(*kingpin.ParseContext) error {
		conf, err := source(path)
		if err != nil {
			return err
		}
		return ShowAuditlog(output, Format(opts.Format), conf, name)
	}).Arg("name", "Name of the audit log.").Required().SetValue(&name)
	eventCmd := parent.Command("events", "Show verified audit events.")
	if local {
		eventCmd.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&opts.ConfigurationPath)
	}
	eventCmd.Flag("name", "Filter by event name.").StringVar(&opts.EventName)
	eventCmd.Flag("flow", "Filter by flow (requires --with-sensitive).").StringVar(&opts.FlowName)
	eventCmd.Flag("since", "Events recorded at or after RFC3339 time.").StringVar(&opts.Since)
	eventCmd.Flag("until", "Events recorded at or before RFC3339 time.").StringVar(&opts.Until)
	eventCmd.Flag("limit", "Limit the number of newest matching events (0 = all).").Default("100").IntVar(&opts.Limit)
	eventCmd.Flag("with-sensitive", "Include private event fields (encrypted journals need a local decryption identity).").BoolVar(&opts.WithSensitive)
	if local {
		eventCmd.Flag("decryptionIdentityFile", "Local private key for encrypted events (repeatable).").StringsVar(&opts.IdentityFiles)
	}
	eventCmd.Arg("name", "Name of the audit log.").Required().SetValue(&opts.Auditlog)
	eventCmd.Action(func(*kingpin.ParseContext) error {
		filter := AuditEventFilter{Name: opts.EventName, Flow: opts.FlowName, Limit: opts.Limit}
		var err error
		if opts.Since != "" {
			if filter.Since, err = time.Parse(time.RFC3339, opts.Since); err != nil {
				return fmt.Errorf("invalid --since: %w", err)
			}
		}
		if opts.Until != "" {
			if filter.Until, err = time.Parse(time.RFC3339, opts.Until); err != nil {
				return fmt.Errorf("invalid --until: %w", err)
			}
		}
		if opts.FlowName != "" && !opts.WithSensitive {
			return fmt.Errorf("--flow requires --with-sensitive")
		}
		records, err := events(ctx, opts.ConfigurationPath, opts.Auditlog, opts.WithSensitive, opts.IdentityFiles)
		if err != nil {
			return err
		}
		return WriteAuditEvents(output, Format(opts.Format), records, filter, opts.WithSensitive)
	})
	return parent, opts
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
