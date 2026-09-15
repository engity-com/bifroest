package configuration

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/template"
)

const (
	// MaximumAuditlogRecordingChunkSizeBytes matches the current BECast
	// plaintext chunk limit without coupling configuration to pkg/recording.
	MaximumAuditlogRecordingChunkSizeBytes uint64 = 1_048_577

	AuditlogRecordingCompressionLevelDefault AuditlogRecordingCompressionLevel = "default"
)

var (
	DefaultAuditlogRecordingEnabled           = false
	DefaultAuditlogRecordingDirectory         = defaultAuditlogRecordingDirectory
	DefaultAuditlogRecordingCompression       = AuditlogRecordingCompression{Level: AuditlogRecordingCompressionLevelDefault}
	DefaultAuditlogRecordingChunkSizeBytes    = uint64(256 << 10)
	DefaultAuditlogRecordingFlushInterval     = common.DurationOf(2 * time.Second)
	DefaultAuditlogRecordingFlushSizeBytes    = uint64(1 << 20)
	DefaultAuditlogRecordingMaximumSpoolBytes = uint64(100 << 30)
	DefaultAuditlogRecordingRetainFor         = common.DurationOf(720 * time.Hour)
	DefaultAuditlogRecordingNotice            = template.MustNewString("")
)

// AuditlogRecording defines local session recording and delivery policy. The
// signing identity and optional encryption recipient are inherited from the
// parent Auditlog.
type AuditlogRecording struct {
	Enabled           bool                         `yaml:"enabled,omitempty"`
	Directory         string                       `yaml:"directory,omitempty"`
	Compression       AuditlogRecordingCompression `yaml:"compression,omitempty"`
	ChunkSizeBytes    uint64                       `yaml:"chunkSizeBytes,omitempty"`
	FlushInterval     common.Duration              `yaml:"flushInterval,omitempty"`
	FlushSizeBytes    uint64                       `yaml:"flushSizeBytes,omitempty"`
	MaximumSpoolBytes uint64                       `yaml:"maximumSpoolBytes,omitempty"`
	RetainFor         common.Duration              `yaml:"retainFor"`
	Notice            template.String              `yaml:"notice,omitempty"`
	Targets           AuditlogRecordingTargets     `yaml:"targets,omitempty"`
}

func (this *AuditlogRecording) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("enabled", func(v *AuditlogRecording) *bool { return &v.Enabled }, DefaultAuditlogRecordingEnabled),
		fixedDefault("directory", func(v *AuditlogRecording) *string { return &v.Directory }, DefaultAuditlogRecordingDirectory),
		fixedDefault("compression", func(v *AuditlogRecording) *AuditlogRecordingCompression { return &v.Compression }, DefaultAuditlogRecordingCompression),
		fixedDefault("chunkSizeBytes", func(v *AuditlogRecording) *uint64 { return &v.ChunkSizeBytes }, DefaultAuditlogRecordingChunkSizeBytes),
		fixedDefault("flushInterval", func(v *AuditlogRecording) *common.Duration { return &v.FlushInterval }, DefaultAuditlogRecordingFlushInterval),
		fixedDefault("flushSizeBytes", func(v *AuditlogRecording) *uint64 { return &v.FlushSizeBytes }, DefaultAuditlogRecordingFlushSizeBytes),
		fixedDefault("maximumSpoolBytes", func(v *AuditlogRecording) *uint64 { return &v.MaximumSpoolBytes }, DefaultAuditlogRecordingMaximumSpoolBytes),
		fixedDefault("retainFor", func(v *AuditlogRecording) *common.Duration { return &v.RetainFor }, DefaultAuditlogRecordingRetainFor),
		fixedDefault("notice", func(v *AuditlogRecording) *template.String { return &v.Notice }, DefaultAuditlogRecordingNotice),
		func(v *AuditlogRecording) (string, defaulter) { return "targets", &v.Targets },
	)
}

func (this *AuditlogRecording) Trim() error {
	return trim(this,
		noopTrim[AuditlogRecording]("enabled"),
		func(v *AuditlogRecording) (string, trimmer) { return "directory", &stringTrimmer{&v.Directory} },
		func(v *AuditlogRecording) (string, trimmer) { return "compression", &v.Compression },
		noopTrim[AuditlogRecording]("chunkSizeBytes"),
		noopTrim[AuditlogRecording]("flushInterval"),
		noopTrim[AuditlogRecording]("flushSizeBytes"),
		noopTrim[AuditlogRecording]("maximumSpoolBytes"),
		noopTrim[AuditlogRecording]("retainFor"),
		noopTrim[AuditlogRecording]("notice"),
		func(v *AuditlogRecording) (string, trimmer) { return "targets", &v.Targets },
	)
}

func (this AuditlogRecording) IsZero() bool {
	return !this.Enabled &&
		this.Directory == "" &&
		this.Compression.Level.IsZero() &&
		this.ChunkSizeBytes == 0 &&
		this.FlushInterval.IsZero() &&
		this.FlushSizeBytes == 0 &&
		this.MaximumSpoolBytes == 0 &&
		this.RetainFor.IsZero() &&
		this.Notice.IsZero() &&
		this.Targets.IsInherited()
}

func (this *AuditlogRecording) Validate() error {
	if this.IsZero() {
		return nil
	}
	return validate(this,
		noopValidate[AuditlogRecording]("enabled"),
		notEmptyStringValidate("directory", func(v *AuditlogRecording) *string { return &v.Directory }),
		func(v *AuditlogRecording) (string, validator) { return "compression", &v.Compression },
		func(v *AuditlogRecording) (string, validator) {
			return "chunkSizeBytes", validatorFunc(func() error {
				if v.ChunkSizeBytes < 1 || v.ChunkSizeBytes > MaximumAuditlogRecordingChunkSizeBytes {
					return fmt.Errorf("must be between 1 and %d", MaximumAuditlogRecordingChunkSizeBytes)
				}
				return nil
			})
		},
		func(v *AuditlogRecording) (string, validator) {
			return "flushInterval", validatorFunc(func() error {
				if err := v.FlushInterval.Validate(); err != nil {
					return err
				}
				if v.FlushInterval.Native() <= 0 {
					return fmt.Errorf("must be positive")
				}
				return nil
			})
		},
		func(v *AuditlogRecording) (string, validator) {
			return "flushSizeBytes", validatorFunc(func() error {
				if v.FlushSizeBytes == 0 {
					return fmt.Errorf("must be positive")
				}
				return nil
			})
		},
		func(v *AuditlogRecording) (string, validator) {
			return "maximumSpoolBytes", validatorFunc(func() error {
				if v.MaximumSpoolBytes == 0 {
					return fmt.Errorf("must be positive")
				}
				if v.MaximumSpoolBytes < v.ChunkSizeBytes {
					return fmt.Errorf("must be greater than or equal to chunkSizeBytes")
				}
				if v.MaximumSpoolBytes < v.FlushSizeBytes {
					return fmt.Errorf("must be greater than or equal to flushSizeBytes")
				}
				return nil
			})
		},
		func(v *AuditlogRecording) (string, validator) {
			return "retainFor", nonNegativeDurationValidator(&v.RetainFor)
		},
		func(v *AuditlogRecording) (string, validator) { return "notice", &v.Notice },
		func(v *AuditlogRecording) (string, validator) { return "targets", &v.Targets },
	)
}

func (this *AuditlogRecording) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogRecording, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "enabled", "directory", "compression", "chunkSizeBytes", "flushInterval", "flushSizeBytes", "maximumSpoolBytes", "retainFor", "notice", "targets"); err != nil {
			return err
		}
		type raw AuditlogRecording
		return node.Decode((*raw)(target))
	})
}

func (this AuditlogRecording) MarshalYAML() (any, error) {
	return struct {
		Enabled           bool                         `yaml:"enabled,omitempty"`
		Directory         string                       `yaml:"directory,omitempty"`
		Compression       AuditlogRecordingCompression `yaml:"compression,omitempty"`
		ChunkSizeBytes    uint64                       `yaml:"chunkSizeBytes,omitempty"`
		FlushInterval     common.Duration              `yaml:"flushInterval,omitempty"`
		FlushSizeBytes    uint64                       `yaml:"flushSizeBytes,omitempty"`
		MaximumSpoolBytes uint64                       `yaml:"maximumSpoolBytes,omitempty"`
		RetainFor         string                       `yaml:"retainFor"`
		Notice            template.String              `yaml:"notice,omitempty"`
		Targets           AuditlogRecordingTargets     `yaml:"targets"`
	}{
		Enabled:           this.Enabled,
		Directory:         this.Directory,
		Compression:       this.Compression,
		ChunkSizeBytes:    this.ChunkSizeBytes,
		FlushInterval:     this.FlushInterval,
		FlushSizeBytes:    this.FlushSizeBytes,
		MaximumSpoolBytes: this.MaximumSpoolBytes,
		RetainFor:         this.RetainFor.Native().String(),
		Notice:            this.Notice,
		Targets:           this.Targets,
	}, nil
}

func (this AuditlogRecording) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogRecording:
		return this.isEqualTo(&value)
	case *AuditlogRecording:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogRecording) isEqualTo(other *AuditlogRecording) bool {
	return this.Enabled == other.Enabled &&
		this.Directory == other.Directory &&
		this.Compression.IsEqualTo(other.Compression) &&
		this.ChunkSizeBytes == other.ChunkSizeBytes &&
		this.FlushInterval.IsEqualTo(other.FlushInterval) &&
		this.FlushSizeBytes == other.FlushSizeBytes &&
		this.MaximumSpoolBytes == other.MaximumSpoolBytes &&
		this.RetainFor.IsEqualTo(other.RetainFor) &&
		this.Notice.IsEqualTo(other.Notice) &&
		this.Targets.IsEqualTo(other.Targets)
}

type AuditlogRecordingCompression struct {
	Level AuditlogRecordingCompressionLevel `yaml:"level,omitempty"`
}

func (this *AuditlogRecordingCompression) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("level", func(v *AuditlogRecordingCompression) *AuditlogRecordingCompressionLevel { return &v.Level }, AuditlogRecordingCompressionLevelDefault),
	)
}

func (this *AuditlogRecordingCompression) Trim() error {
	return trim(this, noopTrim[AuditlogRecordingCompression]("level"))
}

func (this *AuditlogRecordingCompression) Validate() error {
	return validate(this,
		func(v *AuditlogRecordingCompression) (string, validator) { return "level", &v.Level },
	)
}

func (this *AuditlogRecordingCompression) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogRecordingCompression, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "level"); err != nil {
			return err
		}
		type raw AuditlogRecordingCompression
		return node.Decode((*raw)(target))
	})
}

func (this AuditlogRecordingCompression) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogRecordingCompression:
		return this.Level == value.Level
	case *AuditlogRecordingCompression:
		return value != nil && this.Level == value.Level
	default:
		return false
	}
}

type AuditlogRecordingCompressionLevel string

func (this AuditlogRecordingCompressionLevel) IsZero() bool {
	return len(this) == 0
}

func (this AuditlogRecordingCompressionLevel) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this AuditlogRecordingCompressionLevel) String() string {
	return string(this)
}

func (this *AuditlogRecordingCompressionLevel) UnmarshalText(text []byte) error {
	value := AuditlogRecordingCompressionLevel(text)
	if err := value.Validate(); err != nil {
		return err
	}
	*this = value
	return nil
}

func (this *AuditlogRecordingCompressionLevel) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuditlogRecordingCompressionLevel) Validate() error {
	if this != AuditlogRecordingCompressionLevelDefault {
		return fmt.Errorf("illegal compression level: %q", this)
	}
	return nil
}

func (this AuditlogRecordingCompressionLevel) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case string:
		return string(this) == value
	case *string:
		return value != nil && string(this) == *value
	case AuditlogRecordingCompressionLevel:
		return this == value
	case *AuditlogRecordingCompressionLevel:
		return value != nil && this == *value
	default:
		return false
	}
}

func (this AuditlogRecordingCompressionLevel) Clone() AuditlogRecordingCompressionLevel {
	return AuditlogRecordingCompressionLevel(strings.Clone(string(this)))
}

type AuditlogRecordingTargetsMode uint8

const (
	AuditlogRecordingTargetsModeInherit AuditlogRecordingTargetsMode = iota
	AuditlogRecordingTargetsModeDisabled
	AuditlogRecordingTargetsModeCustom
)

// AuditlogRecordingTargets selects inherited or custom required delivery
// targets, or disables remote Recording delivery.
type AuditlogRecordingTargets struct {
	Mode    AuditlogRecordingTargetsMode `yaml:"-"`
	Targets AuditlogTargets              `yaml:"-"`
}

func (this *AuditlogRecordingTargets) SetDefaults() error {
	*this = AuditlogRecordingTargets{}
	return this.Targets.SetDefaults()
}

func (this *AuditlogRecordingTargets) Trim() error {
	if err := this.Targets.Trim(); err != nil {
		return err
	}
	return this.Validate()
}

func (this AuditlogRecordingTargets) Validate() error {
	switch this.Mode {
	case AuditlogRecordingTargetsModeInherit, AuditlogRecordingTargetsModeDisabled:
		if len(this.Targets) != 0 {
			return fmt.Errorf("targets must be empty in inherit or disabled mode")
		}
	case AuditlogRecordingTargetsModeCustom:
		if len(this.Targets) == 0 {
			return fmt.Errorf("custom targets must not be empty")
		}
	default:
		return fmt.Errorf("illegal recording targets mode: %d", this.Mode)
	}
	return this.Targets.Validate()
}

func (this *AuditlogRecordingTargets) UnmarshalYAML(node *yaml.Node) error {
	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	for node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	if auditlogRecordingTargetsYAMLNodeIsNull(node) {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!bool" {
			var enabled bool
			if err := node.Decode(&enabled); err != nil {
				return reportYamlRelatedErr(node, err)
			}
			if enabled {
				return reportYamlRelatedErrf(node, "recording targets cannot be enabled with true")
			}
			this.Mode = AuditlogRecordingTargetsModeDisabled
			return nil
		}
		if node.Tag != "!!str" {
			return reportYamlRelatedErrf(node, "recording targets must be inherit, false, or a nonempty sequence")
		}
		if node.Value == "inherit" {
			return nil
		}
		value := strings.TrimSpace(node.Value)
		switch {
		case strings.EqualFold(value, "false"), strings.EqualFold(value, "off"), strings.EqualFold(value, "no"):
			this.Mode = AuditlogRecordingTargetsModeDisabled
			return nil
		default:
			return reportYamlRelatedErrf(node, "illegal recording targets mode: %q", node.Value)
		}
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return nil
		}
		this.Mode = AuditlogRecordingTargetsModeCustom
		if err := node.Decode(&this.Targets); err != nil {
			return reportYamlRelatedErr(node, err)
		}
		if err := this.Trim(); err != nil {
			return reportYamlRelatedErr(node, err)
		}
		return nil
	default:
		return reportYamlRelatedErrf(node, "recording targets must be inherit, false, or a nonempty sequence")
	}
}

func (this AuditlogRecordingTargets) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	switch this.Mode {
	case AuditlogRecordingTargetsModeInherit:
		return "inherit", nil
	case AuditlogRecordingTargetsModeDisabled:
		return false, nil
	case AuditlogRecordingTargetsModeCustom:
		return this.Targets, nil
	default:
		panic("validated recording targets mode is not supported")
	}
}

func (this AuditlogRecordingTargets) IsInherited() bool {
	return this.Mode == AuditlogRecordingTargetsModeInherit && len(this.Targets) == 0
}

func (this AuditlogRecordingTargets) IsDisabled() bool {
	return this.Mode == AuditlogRecordingTargetsModeDisabled && len(this.Targets) == 0
}

func (this AuditlogRecordingTargets) Configured() AuditlogTargets {
	if this.Mode != AuditlogRecordingTargetsModeCustom {
		return nil
	}
	return this.Targets
}

func (this AuditlogRecordingTargets) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch value := other.(type) {
	case AuditlogRecordingTargets:
		return this.isEqualTo(&value)
	case *AuditlogRecordingTargets:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogRecordingTargets) isEqualTo(other *AuditlogRecordingTargets) bool {
	return this.Mode == other.Mode && this.Targets.IsEqualTo(other.Targets)
}

func auditlogRecordingTargetsYAMLNodeIsNull(node *yaml.Node) bool {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node != nil && node.Tag == "!!null"
}
