package audit

import (
	"fmt"
	"io"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/flow"
	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type AuditEventsOptions struct {
	Format             cliformat.Format
	ConfigurationPath  string
	EventName          string
	FlowName           string
	Since              time.Time
	Until              time.Time
	Auditlog           configuration.AuditlogName
	Limit              uint
	WithSensitive      bool
	IdentityFiles      []string
	ExpectedProducerID string
}

func ListAuditlogs(output io.Writer, selected cliformat.Format, conf *configuration.Configuration) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	entries := make([]model.AuditlogSummary, 0, len(conf.Auditlogs))
	for _, current := range conf.Auditlogs {
		entries = append(entries, model.AuditlogSummary{
			Name: current.Name, Enabled: current.Enabled, RecordingEnabled: current.Recording.Enabled,
			Encrypted: !current.EncryptionPublicKey.IsZero() || !current.EncryptionPublicKeyFile.IsZero(),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return cliformat.WriteAuditlogList(output, selected, entries)
}

func ShowAuditlog(output io.Writer, selected cliformat.Format, conf *configuration.Configuration, name configuration.AuditlogName) error {
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
		flow.RedactSettings(settings)
		return cliformat.WriteSettings(output, selected, settings)
	}
	return fmt.Errorf("auditlog %q does not exist", name)
}
