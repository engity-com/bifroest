package configuration

import (
	"fmt"
	"path/filepath"
	"strings"

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
	Name         AuditlogName    `yaml:"name"`
	Enabled      bool            `yaml:"enabled,omitempty"`
	IdentityFile string          `yaml:"identityFile,omitempty"`
	Journal      AuditlogJournal `yaml:"journal,omitempty"`
}

func (this *Auditlog) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("name", func(v *Auditlog) *AuditlogName { return &v.Name }, DefaultAuditlogName),
		fixedDefault("enabled", func(v *Auditlog) *bool { return &v.Enabled }, DefaultAuditlogEnabled),
		fixedDefault("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }, DefaultAuditlogIdentityFile),
		func(v *Auditlog) (string, defaulter) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) Trim() error {
	return trim(this,
		noopTrim[Auditlog]("name"),
		noopTrim[Auditlog]("enabled"),
		func(v *Auditlog) (string, trimmer) { return "identityFile", &stringTrimmer{&v.IdentityFile} },
		func(v *Auditlog) (string, trimmer) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) Validate() error {
	return validate(this,
		func(v *Auditlog) (string, validator) { return "name", &v.Name },
		noopValidate[Auditlog]("enabled"),
		notEmptyStringValidate("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }),
		func(v *Auditlog) (string, validator) { return "journal", &v.Journal },
	)
}

func (this *Auditlog) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Auditlog, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "name", "enabled", "identityFile", "journal"); err != nil {
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
	return this.Name == other.Name &&
		this.Enabled == other.Enabled &&
		this.IdentityFile == other.IdentityFile &&
		isEqual(&this.Journal, &other.Journal)
}

type Auditlogs []Auditlog

func (this *Auditlogs) SetDefaults() error {
	return setSliceDefaults(this, Auditlog{Name: DefaultAuditlogName})
}

func (this Auditlogs) IsZero() bool {
	return len(this) == 0
}

func (this *Auditlogs) Trim() error {
	if len(*this) == 0 {
		if err := this.SetDefaults(); err != nil {
			return err
		}
	}
	if err := trimSlice(this); err != nil {
		return err
	}
	return this.validateUniqueNames()
}

func (this Auditlogs) Validate() error {
	if err := this.validateUniqueNames(); err != nil {
		return err
	}
	if err := validateSlice(this); err != nil {
		return err
	}
	identityFiles := make(map[string]int)
	journalDirectories := make(map[string]int)
	for index, auditlog := range this {
		if !auditlog.Enabled {
			continue
		}
		if previous, exists := identityFiles[auditlog.IdentityFile]; exists {
			return fmt.Errorf("[%d][identityFile] duplicates enabled auditlog [%d][identityFile] %q", index, previous, auditlog.IdentityFile)
		}
		identityFiles[auditlog.IdentityFile] = index
		if previous, exists := journalDirectories[auditlog.Journal.Directory]; exists {
			return fmt.Errorf("[%d][journal][directory] duplicates enabled auditlog [%d][journal][directory] %q", index, previous, auditlog.Journal.Directory)
		}
		journalDirectories[auditlog.Journal.Directory] = index
	}
	for leftIndex, left := range this {
		if !left.Enabled {
			continue
		}
		for rightIndex, right := range this {
			if !right.Enabled {
				continue
			}
			if leftIndex < rightIndex && (pathContains(left.Journal.Directory, right.Journal.Directory) || pathContains(right.Journal.Directory, left.Journal.Directory)) {
				return fmt.Errorf("[%d][journal][directory] overlaps enabled auditlog [%d][journal][directory]", rightIndex, leftIndex)
			}
			if pathContains(left.IdentityFile, right.Journal.Directory) {
				return fmt.Errorf("[%d][identityFile] is located inside enabled auditlog [%d][journal][directory]", leftIndex, rightIndex)
			}
			if pathContains(right.Journal.Directory, left.IdentityFile) {
				return fmt.Errorf("[%d][journal][directory] is located below enabled auditlog [%d][identityFile]", rightIndex, leftIndex)
			}
			if leftIndex < rightIndex && (pathContains(left.IdentityFile, right.IdentityFile) || pathContains(right.IdentityFile, left.IdentityFile)) {
				return fmt.Errorf("[%d][identityFile] overlaps enabled auditlog [%d][identityFile]", rightIndex, leftIndex)
			}
		}
	}
	return nil
}

func pathContains(path, directory string) bool {
	absolutePath, pathErr := filepath.Abs(path)
	absoluteDirectory, directoryErr := filepath.Abs(directory)
	if pathErr != nil || directoryErr != nil {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(absoluteDirectory), filepath.Clean(absolutePath))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (this Auditlogs) validateUniqueNames() error {
	indices := make(map[AuditlogName]int, len(this))
	for index, auditlog := range this {
		if previous, exists := indices[auditlog.Name]; exists {
			return fmt.Errorf("[%d][name] duplicates [%d][name] %q", index, previous, auditlog.Name)
		}
		indices[auditlog.Name] = index
	}
	return nil
}

func (this *Auditlogs) UnmarshalYAML(node *yaml.Node) error {
	*this = Auditlogs{}
	return unmarshalYAML(this, node, func(target *Auditlogs, node *yaml.Node) error {
		type raw Auditlogs
		return node.Decode((*raw)(target))
	})
}

func (this Auditlogs) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case Auditlogs:
		return this.isEqualTo(&value)
	case *Auditlogs:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this Auditlogs) isEqualTo(other *Auditlogs) bool {
	if len(this) != len(*other) {
		return false
	}
	for index, auditlog := range this {
		if !auditlog.IsEqualTo((*other)[index]) {
			return false
		}
	}
	return true
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
