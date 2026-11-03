package configuration

import (
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
)

var (
	DefaultAuditlogFailurePolicy           = AuditlogFailurePolicyStrict
	DefaultAuditlogIdentityFile            = defaultAuditlogIdentityFile
	DefaultAuditlogJournalDirectory        = defaultAuditlogJournalDirectory
	DefaultAuditlogJournalMinimumFreeBytes = uint64(256 << 20)
)

// Auditlog defines the authoritative local audit journal and optional remote
// targets that replicate its immutable sealed segments.
type Auditlog struct {
	Name                    AuditlogName          `yaml:"-"`
	FailurePolicy           AuditlogFailurePolicy `yaml:"failurePolicy,omitempty"`
	IdentityFile            string                `yaml:"identityFile,omitempty"`
	EncryptionPublicKey     crypto.PublicKeys     `yaml:"encryptionPublicKey,omitempty"`
	EncryptionPublicKeyFile crypto.PublicKeysFile `yaml:"encryptionPublicKeyFile,omitempty"`
	Directory               string                `yaml:"directory,omitempty"`
	MinimumFreeBytes        uint64                `yaml:"minimumFreeBytes"`
	Recording               AuditlogRecording     `yaml:"recording,omitempty"`
	Targets                 AuditlogTargets       `yaml:"targets,omitempty"`
}

func (this *Auditlog) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("name", func(v *Auditlog) *AuditlogName { return &v.Name }, DefaultAuditlogName),
		fixedDefault("failurePolicy", func(v *Auditlog) *AuditlogFailurePolicy { return &v.FailurePolicy }, DefaultAuditlogFailurePolicy),
		fixedDefault("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }, DefaultAuditlogIdentityFile),
		noopSetDefault[Auditlog]("encryptionPublicKey"),
		noopSetDefault[Auditlog]("encryptionPublicKeyFile"),
		fixedDefault("directory", func(v *Auditlog) *string { return &v.Directory }, DefaultAuditlogJournalDirectory),
		fixedDefault("minimumFreeBytes", func(v *Auditlog) *uint64 { return &v.MinimumFreeBytes }, DefaultAuditlogJournalMinimumFreeBytes),
		func(v *Auditlog) (string, defaulter) { return "recording", &v.Recording },
		func(v *Auditlog) (string, defaulter) { return "targets", &v.Targets },
	)
}

func (this *Auditlog) Trim() error {
	return trim(this,
		noopTrim[Auditlog]("name"),
		noopTrim[Auditlog]("failurePolicy"),
		func(v *Auditlog) (string, trimmer) { return "identityFile", &stringTrimmer{&v.IdentityFile} },
		func(v *Auditlog) (string, trimmer) { return "encryptionPublicKey", &v.EncryptionPublicKey },
		func(v *Auditlog) (string, trimmer) { return "encryptionPublicKeyFile", &v.EncryptionPublicKeyFile },
		func(v *Auditlog) (string, trimmer) { return "directory", &stringTrimmer{&v.Directory} },
		noopTrim[Auditlog]("minimumFreeBytes"),
		func(v *Auditlog) (string, trimmer) { return "recording", &v.Recording },
		func(v *Auditlog) (string, trimmer) { return "targets", &v.Targets },
	)
}

func (this *Auditlog) Validate() error {
	if !this.EncryptionPublicKey.IsZero() && !this.EncryptionPublicKeyFile.IsZero() {
		return fmt.Errorf("[encryptionPublicKey] cannot be combined with [encryptionPublicKeyFile]")
	}
	if err := validate(this,
		func(v *Auditlog) (string, validator) { return "name", &v.Name },
		func(v *Auditlog) (string, validator) { return "failurePolicy", &v.FailurePolicy },
		notEmptyStringValidate("identityFile", func(v *Auditlog) *string { return &v.IdentityFile }),
		func(v *Auditlog) (string, validator) {
			return "encryptionPublicKey", &auditlogEncryptionPublicKeyValidator{v.EncryptionPublicKey}
		},
		noopValidate[Auditlog]("encryptionPublicKeyFile"),
		notEmptyStringValidate("directory", func(v *Auditlog) *string { return &v.Directory }),
		noopValidate[Auditlog]("minimumFreeBytes"),
		func(v *Auditlog) (string, validator) { return "recording", &v.Recording },
		func(v *Auditlog) (string, validator) { return "targets", &v.Targets },
	); err != nil {
		return err
	}
	return nil
}

func (this *Auditlog) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Auditlog, node *yaml.Node) error {
		if err := rejectUnknownConfigurationFields(node, target); err != nil {
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
		this.FailurePolicy.IsEqualTo(other.FailurePolicy) &&
		this.IdentityFile == other.IdentityFile &&
		this.EncryptionPublicKey.IsEqualTo(other.EncryptionPublicKey) &&
		this.EncryptionPublicKeyFile.IsEqualTo(other.EncryptionPublicKeyFile) &&
		this.Directory == other.Directory &&
		this.MinimumFreeBytes == other.MinimumFreeBytes &&
		isEqual(&this.Recording, &other.Recording) &&
		isEqual(&this.Targets, &other.Targets)
}

type auditlogEncryptionPublicKeyValidator struct {
	crypto.PublicKeys
}

func (this auditlogEncryptionPublicKeyValidator) Validate() error {
	if this.IsZero() {
		return nil
	}
	keys, err := this.Get()
	if err != nil {
		return err
	}
	return ValidateAuditlogEncryptionPublicKeys(keys)
}

// ValidateAuditlogEncryptionPublicKeys enforces the audit age recipient key policy.
func ValidateAuditlogEncryptionPublicKeys(keys []ssh.PublicKey) error {
	if len(keys) != 1 {
		return fmt.Errorf("exactly one SSH public key is required")
	}
	switch keys[0].Type() {
	case ssh.KeyAlgoED25519:
		return nil
	case ssh.KeyAlgoRSA:
		cryptoKey, ok := keys[0].(ssh.CryptoPublicKey)
		if !ok {
			return fmt.Errorf("SSH RSA public key cannot be used for encryption")
		}
		rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("SSH RSA public key must contain at least 2048 bits")
		}
		return nil
	default:
		return fmt.Errorf("SSH public key type %q cannot be used for encryption", keys[0].Type())
	}
}

type Auditlogs []Auditlog

func (this *Auditlogs) SetDefaults() error {
	return setSliceDefaults(this)
}

func (this Auditlogs) IsZero() bool {
	return len(this) == 0
}

func (this *Auditlogs) Trim() error {
	slices.SortFunc(*this, func(left, right Auditlog) int { return strings.Compare(string(left.Name), string(right.Name)) })
	if err := trimSlice(this); err != nil {
		return err
	}
	return this.Validate()
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
		if previous, exists := identityFiles[auditlog.IdentityFile]; exists {
			return fmt.Errorf("[%d][identityFile] duplicates auditlog [%d][identityFile] %q", index, previous, auditlog.IdentityFile)
		}
		identityFiles[auditlog.IdentityFile] = index
		if previous, exists := journalDirectories[auditlog.Directory]; exists {
			return fmt.Errorf("[%d][directory] duplicates auditlog [%d][directory] %q", index, previous, auditlog.Directory)
		}
		journalDirectories[auditlog.Directory] = index
	}
	for leftIndex, left := range this {
		for rightIndex, right := range this {
			if leftIndex < rightIndex && pathsOverlap(left.Directory, right.Directory) {
				return fmt.Errorf("[%d][directory] overlaps auditlog [%d][directory]", rightIndex, leftIndex)
			}
			if pathContains(left.IdentityFile, right.Directory) {
				return fmt.Errorf("[%d][identityFile] is located inside auditlog [%d][directory]", leftIndex, rightIndex)
			}
			if pathContains(right.Directory, left.IdentityFile) {
				return fmt.Errorf("[%d][directory] is located below auditlog [%d][identityFile]", rightIndex, leftIndex)
			}
			if leftIndex < rightIndex && pathsOverlap(left.IdentityFile, right.IdentityFile) {
				return fmt.Errorf("[%d][identityFile] overlaps auditlog [%d][identityFile]", rightIndex, leftIndex)
			}
		}
	}
	for recordingIndex, recordingAuditlog := range this {
		if !recordingAuditlog.Recording.Enabled {
			continue
		}
		recordingDirectory := recordingAuditlog.Recording.Directory
		for auditlogIndex, auditlog := range this {
			if pathsOverlap(recordingDirectory, auditlog.Directory) {
				return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][directory]", recordingIndex, auditlogIndex)
			}
			if pathsOverlap(recordingDirectory, auditlog.IdentityFile) {
				return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][identityFile]", recordingIndex, auditlogIndex)
			}
			if recordingIndex < auditlogIndex && auditlog.Recording.Enabled && pathsOverlap(recordingDirectory, auditlog.Recording.Directory) {
				return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][recording][directory]", auditlogIndex, recordingIndex)
			}
			if !auditlog.EncryptionPublicKeyFile.IsZero() && pathsOverlap(recordingDirectory, string(auditlog.EncryptionPublicKeyFile)) {
				return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][encryptionPublicKeyFile]", recordingIndex, auditlogIndex)
			}
			for targetIndex, target := range auditlog.Targets {
				sftp, ok := target.V.(*AuditlogTargetSftp)
				if !ok || sftp == nil {
					continue
				}
				if !sftp.KnownHostsFile.IsZero() && pathsOverlap(recordingDirectory, string(sftp.KnownHostsFile)) {
					return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][targets][%d][knownHostsFile]", recordingIndex, auditlogIndex, targetIndex)
				}
				for identityIndex, identityFile := range sftp.IdentityFiles {
					if pathsOverlap(recordingDirectory, identityFile) {
						return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][targets][%d][identityFiles][%d]", recordingIndex, auditlogIndex, targetIndex, identityIndex)
					}
				}
			}
			if !auditlog.Recording.Enabled {
				continue
			}
			for targetIndex, target := range auditlog.Recording.Targets.Configured() {
				sftp, ok := target.V.(*AuditlogTargetSftp)
				if !ok || sftp == nil {
					continue
				}
				if !sftp.KnownHostsFile.IsZero() && pathsOverlap(recordingDirectory, string(sftp.KnownHostsFile)) {
					return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][recording][targets][%d][knownHostsFile]", recordingIndex, auditlogIndex, targetIndex)
				}
				for identityIndex, identityFile := range sftp.IdentityFiles {
					if pathsOverlap(recordingDirectory, identityFile) {
						return fmt.Errorf("[%d][recording][directory] overlaps auditlog [%d][recording][targets][%d][identityFiles][%d]", recordingIndex, auditlogIndex, targetIndex, identityIndex)
					}
				}
			}
		}
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	return pathContains(left, right) || pathContains(right, left)
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
	var entries map[string]Auditlog
	if err := decodeDefinitions(node, &entries); err != nil {
		return err
	}
	result := make(Auditlogs, 0, len(entries))
	for _, name := range definitionKeys(entries) {
		value := entries[name]
		value.Name = AuditlogName(name)
		result = append(result, value)
	}
	if err := result.Validate(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	*this = result
	return nil
}

func (this Auditlogs) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	result := make(map[string]Auditlog, len(this))
	for _, value := range this {
		result[string(value.Name)] = value
	}
	return result, nil
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
	entries := make(map[AuditlogName]Auditlog, len(this))
	for _, auditlog := range this {
		entries[auditlog.Name] = auditlog
	}
	if len(entries) != len(this) {
		return false
	}
	for _, auditlog := range *other {
		entry, exists := entries[auditlog.Name]
		if !exists || !entry.IsEqualTo(auditlog) {
			return false
		}
		delete(entries, auditlog.Name)
	}
	return true
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
