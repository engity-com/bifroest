package configuration

import (
	"fmt"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/template"
)

const maximumAuditlogTargetSftpPasswordLength = 64 * 1024

var DefaultAuditlogTargetSftpConnectTimeout = template.DurationOf(10 * time.Second)

type AuditlogTargetSftp struct {
	Address           string                `yaml:"address"`
	User              template.String       `yaml:"user"`
	Directory         string                `yaml:"directory"`
	KnownHosts        crypto.KnownHosts     `yaml:"knownHosts,omitempty"`
	KnownHostsFile    crypto.KnownHostsFile `yaml:"knownHostsFile,omitempty"`
	AcceptAllHostKeys bool                  `yaml:"acceptAllHostKeys,omitempty"`
	IdentityFiles     []string              `yaml:"identityFiles,omitempty"`
	Password          template.String       `yaml:"password,omitempty"`
	ConnectTimeout    template.Duration     `yaml:"connectTimeout,omitempty"`
}

func (this *AuditlogTargetSftp) SetDefaults() error {
	*this = AuditlogTargetSftp{ConnectTimeout: DefaultAuditlogTargetSftpConnectTimeout}
	return nil
}

func (this *AuditlogTargetSftp) Trim() error {
	this.Address = strings.TrimSpace(this.Address)
	if this.Address != "" {
		if address, err := bfssh.ParseAddress(this.Address); err == nil {
			this.Address = address.String()
		}
	}
	this.Directory = strings.TrimSpace(this.Directory)
	if this.Directory != "/" {
		this.Directory = strings.TrimSuffix(this.Directory, "/")
	}
	_ = this.KnownHosts.Trim()
	_ = this.KnownHostsFile.Trim()
	for index := range this.IdentityFiles {
		this.IdentityFiles[index] = strings.TrimSpace(this.IdentityFiles[index])
	}
	return this.Validate()
}

func (this *AuditlogTargetSftp) Validate() error {
	if this.Address == "" {
		return fmt.Errorf("[address] required but absent")
	}
	if _, err := bfssh.ParseAddress(this.Address); err != nil {
		return fmt.Errorf("[address] %w", err)
	}
	if err := this.User.Validate(); err != nil {
		return fmt.Errorf("[user] %w", err)
	}
	if this.User.IsZero() {
		return fmt.Errorf("[user] required but absent")
	}
	if err := validateAuditlogTargetSftpDirectory(this.Directory); err != nil {
		return fmt.Errorf("[directory] %w", err)
	}
	if this.AcceptAllHostKeys && (!this.KnownHosts.IsZero() || !this.KnownHostsFile.IsZero()) {
		return fmt.Errorf("[acceptAllHostKeys] cannot be combined with knownHosts or knownHostsFile")
	}
	if !this.AcceptAllHostKeys && this.KnownHosts.IsZero() && this.KnownHostsFile.IsZero() {
		return fmt.Errorf("[knownHosts] or [knownHostsFile] required unless [acceptAllHostKeys] is true")
	}
	if err := this.KnownHosts.ValidateSyntax(); err != nil {
		return fmt.Errorf("[knownHosts] %w", err)
	}
	if err := this.Password.Validate(); err != nil {
		return fmt.Errorf("[password] %w", err)
	}
	if len(this.IdentityFiles) == 0 && this.Password.IsZero() {
		return fmt.Errorf("[identityFiles] or [password] required")
	}
	if len(this.IdentityFiles) > 0 && !this.Password.IsZero() {
		return fmt.Errorf("[identityFiles] cannot be combined with [password]")
	}
	identities := make(map[string]int, len(this.IdentityFiles))
	for index, identity := range this.IdentityFiles {
		if identity == "" {
			return fmt.Errorf("[identityFiles][%d] required but absent", index)
		}
		if previous, exists := identities[identity]; exists {
			return fmt.Errorf("[identityFiles][%d] duplicates [%d] %q", index, previous, identity)
		}
		identities[identity] = index
	}
	if err := this.ConnectTimeout.Validate(); err != nil {
		return fmt.Errorf("[connectTimeout] %w", err)
	}
	if this.ConnectTimeout.IsZero() {
		return fmt.Errorf("[connectTimeout] cannot be empty")
	}
	if this.ConnectTimeout.IsHardCoded() {
		value, err := this.ConnectTimeout.Render(nil)
		if err != nil {
			return fmt.Errorf("[connectTimeout] %w", err)
		}
		if value < 0 {
			return fmt.Errorf("[connectTimeout] cannot be negative")
		}
	}
	return nil
}

type AuditlogTargetSftpValues struct {
	User           string
	Password       string
	ConnectTimeout time.Duration
}

func (this AuditlogTargetSftp) Render(data any) (result AuditlogTargetSftpValues, err error) {
	if result.User, err = this.User.Render(data); err != nil {
		return result, fmt.Errorf("[user] cannot render: %w", err)
	}
	result.User = strings.TrimSpace(result.User)
	if result.User == "" {
		return result, fmt.Errorf("[user] required but absent after rendering")
	}
	if len(result.User) > 255 {
		return result, fmt.Errorf("[user] exceeds 255 bytes after rendering")
	}
	for _, character := range result.User {
		if character < 0x20 || character == 0x7f {
			return result, fmt.Errorf("[user] contains a control character after rendering")
		}
	}
	if !this.Password.IsZero() {
		if result.Password, err = this.Password.Render(data); err != nil {
			return result, fmt.Errorf("[password] cannot render: %w", err)
		}
		if result.Password == "" {
			return result, fmt.Errorf("[password] required but absent after rendering")
		}
		if len(result.Password) > maximumAuditlogTargetSftpPasswordLength {
			return result, fmt.Errorf("[password] exceeds %d bytes after rendering", maximumAuditlogTargetSftpPasswordLength)
		}
	}
	if result.ConnectTimeout, err = this.ConnectTimeout.Render(data); err != nil {
		return result, fmt.Errorf("[connectTimeout] cannot render: %w", err)
	}
	if result.ConnectTimeout < 0 {
		return result, fmt.Errorf("[connectTimeout] cannot be negative after rendering")
	}
	return result, nil
}

func validateAuditlogTargetSftpDirectory(value string) error {
	if value == "" {
		return fmt.Errorf("required but absent")
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("is not valid UTF-8")
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("must be an absolute POSIX path")
	}
	if strings.ContainsRune(value, '\\') {
		return fmt.Errorf("contains a backslash")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("contains a control character")
		}
	}
	if path.Clean(value) != value {
		return fmt.Errorf("contains an empty or relative path component")
	}
	return nil
}

func (this *AuditlogTargetSftp) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogTargetSftp, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "address", "user", "directory", "knownHosts", "knownHostsFile", "acceptAllHostKeys", "identityFiles", "password", "connectTimeout"); err != nil {
			return err
		}
		type raw AuditlogTargetSftp
		return node.Decode((*raw)(target))
	})
}

func (this AuditlogTargetSftp) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case AuditlogTargetSftp:
		return this.isEqualTo(&value)
	case *AuditlogTargetSftp:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogTargetSftp) isEqualTo(other *AuditlogTargetSftp) bool {
	if this.Address != other.Address || !this.User.IsEqualTo(other.User) || this.Directory != other.Directory ||
		!this.KnownHosts.IsEqualTo(other.KnownHosts) || !this.KnownHostsFile.IsEqualTo(other.KnownHostsFile) ||
		this.AcceptAllHostKeys != other.AcceptAllHostKeys || !this.Password.IsEqualTo(other.Password) ||
		!this.ConnectTimeout.IsEqualTo(other.ConnectTimeout) || len(this.IdentityFiles) != len(other.IdentityFiles) {
		return false
	}
	for index := range this.IdentityFiles {
		if this.IdentityFiles[index] != other.IdentityFiles[index] {
			return false
		}
	}
	return true
}

func (this AuditlogTargetSftp) Types() []string {
	return []string{"sftp"}
}

func (this AuditlogTargetSftp) FeatureFlags() []string {
	return []string{"sftp"}
}
