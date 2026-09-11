package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

var (
	DefaultAuditlogEnabled          = false
	DefaultAuditlogIdentityFile     = defaultAuditlogIdentityFile
	DefaultAuditlogJournalDirectory = defaultAuditlogJournalDirectory
)

// Auditlog defines the local audit journal. Remote targets are configured
// separately because they replicate the journal rather than replace it.
type Auditlog struct {
	Enabled      bool            `yaml:"enabled,omitempty"`
	IdentityFile string          `yaml:"identityFile,omitempty"`
	Journal      AuditlogJournal `yaml:"journal,omitempty"`
}

func (this *Auditlog) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("enabled", func(v *Auditlog) *bool { return &v.Enabled }, DefaultAuditlogEnabled),
		fixedDefault("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }, DefaultAuditlogIdentityFile),
		func(v *Auditlog) (string, defaulter) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) Trim() error {
	return trim(this,
		noopTrim[Auditlog]("enabled"),
		func(v *Auditlog) (string, trimmer) { return "identityFile", &stringTrimmer{&v.IdentityFile} },
		func(v *Auditlog) (string, trimmer) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) Validate() error {
	return validate(this,
		noopValidate[Auditlog]("enabled"),
		notEmptyStringValidate("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }),
		func(v *Auditlog) (string, validator) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Auditlog, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "enabled", "identityFile", "journal"); err != nil {
			return err
		}
		type raw Auditlog
		return node.Decode((*raw)(target))
	})
}

func (this Auditlog) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Auditlog:
		return this.isEqualTo(&v)
	case *Auditlog:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this Auditlog) isEqualTo(other *Auditlog) bool {
	return this.Enabled == other.Enabled &&
		this.IdentityFile == other.IdentityFile &&
		isEqual(&this.Journal, &other.Journal)
}

type AuditlogJournal struct {
	Directory string `yaml:"directory,omitempty"`
}

func (this *AuditlogJournal) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("directory", func(v *AuditlogJournal) *string { return &v.Directory }, DefaultAuditlogJournalDirectory),
	)
}

func (this *AuditlogJournal) Trim() error {
	return trim(this,
		func(v *AuditlogJournal) (string, trimmer) { return "directory", &stringTrimmer{&v.Directory} },
	)
}

func (this *AuditlogJournal) Validate() error {
	return validate(this,
		notEmptyStringValidate("directory", func(v *AuditlogJournal) *string { return &v.Directory }),
	)
}

func (this *AuditlogJournal) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogJournal, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "directory"); err != nil {
			return err
		}
		type raw AuditlogJournal
		return node.Decode((*raw)(target))
	})
}

func (this AuditlogJournal) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuditlogJournal:
		return this.Directory == v.Directory
	case *AuditlogJournal:
		return v != nil && this.Directory == v.Directory
	default:
		return false
	}
}

func rejectUnknownAuditlogFields(node *yaml.Node, known ...string) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		for _, candidate := range known {
			if key.Value == candidate {
				key = nil
				break
			}
		}
		if key != nil {
			return reportYamlRelatedErr(key, fmt.Errorf("field %s not found", key.Value))
		}
	}
	return nil
}
