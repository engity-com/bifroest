package configuration

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	smithyhttp "github.com/aws/smithy-go/transport/http"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultAuditlogTargetWebdavUsername = template.MustNewString("")
	DefaultAuditlogTargetWebdavPassword = template.MustNewString("")
)

type AuditlogTargetWebdav struct {
	Endpoint string          `yaml:"endpoint"`
	Username template.String `yaml:"username,omitempty"`
	Password template.String `yaml:"password,omitempty"`
}

func (this *AuditlogTargetWebdav) SetDefaults() error {
	*this = AuditlogTargetWebdav{
		Username: DefaultAuditlogTargetWebdavUsername,
		Password: DefaultAuditlogTargetWebdavPassword,
	}
	return nil
}

func (this *AuditlogTargetWebdav) Trim() error {
	this.Endpoint = strings.TrimSpace(this.Endpoint)
	if this.Endpoint != "" && !strings.HasSuffix(this.Endpoint, "/") {
		this.Endpoint += "/"
	}
	return this.Validate()
}

func (this *AuditlogTargetWebdav) Validate() error {
	if err := validateAuditlogTargetWebdavEndpoint(this.Endpoint); err != nil {
		return fmt.Errorf("[endpoint] %w", err)
	}
	if err := this.Username.Validate(); err != nil {
		return fmt.Errorf("[username] %w", err)
	}
	if err := this.Password.Validate(); err != nil {
		return fmt.Errorf("[password] %w", err)
	}
	if this.Username.IsZero() != this.Password.IsZero() {
		return fmt.Errorf("[username] and [password] must either both be configured or both be omitted")
	}
	return nil
}

type AuditlogTargetWebdavValues struct {
	Username string
	Password string
}

func (this AuditlogTargetWebdav) Render(data any) (result AuditlogTargetWebdavValues, err error) {
	if this.Username.IsZero() && this.Password.IsZero() {
		return result, nil
	}
	if result.Username, err = this.Username.Render(data); err != nil {
		return result, fmt.Errorf("[username] cannot render: %w", err)
	}
	if result.Username == "" {
		return result, fmt.Errorf("[username] required but absent after rendering")
	}
	if strings.ContainsRune(result.Username, ':') {
		return result, fmt.Errorf("[username] must not contain a colon after rendering")
	}
	for _, character := range result.Username {
		if character < 0x20 || character == 0x7f {
			return result, fmt.Errorf("[username] contains a control character after rendering")
		}
	}
	if result.Password, err = this.Password.Render(data); err != nil {
		return result, fmt.Errorf("[password] cannot render: %w", err)
	}
	if result.Password == "" {
		return result, fmt.Errorf("[password] required but absent after rendering")
	}
	for _, character := range result.Password {
		if character < 0x20 || character == 0x7f {
			return result, fmt.Errorf("[password] contains a control character after rendering")
		}
	}
	return result, nil
}

func validateAuditlogTargetWebdavEndpoint(value string) error {
	if value == "" {
		return fmt.Errorf("required but absent")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("cannot parse URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("must be an absolute HTTPS URL")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("contains an empty port")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return fmt.Errorf("contains an invalid port %q", port)
		}
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		if err := smithyhttp.ValidateEndpointHost(parsed.Host); err != nil {
			return fmt.Errorf("contains an invalid host: %w", err)
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.ContainsRune(value, '#') {
		return fmt.Errorf("must not contain user information, a query, or a fragment")
	}
	if !utf8.ValidString(parsed.Path) {
		return fmt.Errorf("path is not valid UTF-8")
	}
	escapedPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") {
		return fmt.Errorf("path contains an encoded path separator")
	}
	if strings.Contains(escapedPath, "%25") {
		return fmt.Errorf("path contains a multiply encoded sequence")
	}
	for _, character := range parsed.Path {
		if character == '\\' {
			return fmt.Errorf("path contains a backslash")
		}
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("path contains a control character")
		}
	}
	if parsed.Path != "" && parsed.Path != "/" {
		pathWithoutTrailingSlash := strings.TrimSuffix(parsed.Path, "/")
		for _, component := range strings.Split(strings.TrimPrefix(pathWithoutTrailingSlash, "/"), "/") {
			if component == "." || component == ".." || component == "" {
				return fmt.Errorf("path contains an empty or relative component")
			}
		}
	}
	return nil
}

func (this *AuditlogTargetWebdav) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogTargetWebdav, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "endpoint", "username", "password"); err != nil {
			return err
		}
		type raw AuditlogTargetWebdav
		return node.Decode((*raw)(target))
	})
}

func (this AuditlogTargetWebdav) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case AuditlogTargetWebdav:
		return this.isEqualTo(&value)
	case *AuditlogTargetWebdav:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogTargetWebdav) isEqualTo(other *AuditlogTargetWebdav) bool {
	return this.Endpoint == other.Endpoint &&
		this.Username.IsEqualTo(other.Username) &&
		this.Password.IsEqualTo(other.Password)
}

func (this AuditlogTargetWebdav) Types() []string {
	return []string{"webdav", "web-dav", "web_dav"}
}

func (this AuditlogTargetWebdav) FeatureFlags() []string {
	return []string{"webdav"}
}
