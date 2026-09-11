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

const maximumAuditlogTargetS3PrefixLength = 857

var (
	DefaultAuditlogTargetS3Region          = template.MustNewString("{{ env `AWS_REGION` | default (env `AWS_DEFAULT_REGION`) }}")
	DefaultAuditlogTargetS3AccessKeyId     = template.MustNewString("{{ env `AWS_ACCESS_KEY_ID` | default (env `AWS_ACCESS_KEY`) }}")
	DefaultAuditlogTargetS3SecretAccessKey = template.MustNewString("{{ env `AWS_SECRET_ACCESS_KEY` | default (env `AWS_SECRET_KEY`) }}")
	DefaultAuditlogTargetS3SessionToken    = template.MustNewString("{{ env `AWS_SESSION_TOKEN` }}")
)

type AuditlogTargetS3 struct {
	Bucket              string          `yaml:"bucket"`
	Region              template.String `yaml:"region,omitempty"`
	Prefix              string          `yaml:"prefix,omitempty"`
	Endpoint            string          `yaml:"endpoint,omitempty"`
	PathStyle           bool            `yaml:"pathStyle,omitempty"`
	ExpectedBucketOwner string          `yaml:"expectedBucketOwner,omitempty"`
	AccessKeyId         template.String `yaml:"accessKeyId,omitempty"`
	SecretAccessKey     template.String `yaml:"secretAccessKey,omitempty"`
	SessionToken        template.String `yaml:"sessionToken,omitempty"`
	sessionTokenDefault bool
}

func (this *AuditlogTargetS3) SetDefaults() error {
	*this = AuditlogTargetS3{
		Region:              DefaultAuditlogTargetS3Region,
		AccessKeyId:         DefaultAuditlogTargetS3AccessKeyId,
		SecretAccessKey:     DefaultAuditlogTargetS3SecretAccessKey,
		SessionToken:        DefaultAuditlogTargetS3SessionToken,
		sessionTokenDefault: true,
	}
	return nil
}

func (this *AuditlogTargetS3) Trim() error {
	this.Bucket = strings.TrimSpace(this.Bucket)
	this.Prefix = strings.TrimSpace(this.Prefix)
	this.Endpoint = strings.TrimSpace(this.Endpoint)
	this.Endpoint = strings.TrimSuffix(this.Endpoint, "/")
	this.ExpectedBucketOwner = strings.TrimSpace(this.ExpectedBucketOwner)
	return this.Validate()
}

func (this *AuditlogTargetS3) Validate() error {
	if err := validateAuditlogTargetS3Bucket(this.Bucket); err != nil {
		return fmt.Errorf("[bucket] %w", err)
	}
	if err := validateAuditlogTargetS3RegionTemplate(this.Region); err != nil {
		return fmt.Errorf("[region] %w", err)
	}
	if err := validateAuditlogTargetS3Prefix(this.Prefix); err != nil {
		return fmt.Errorf("[prefix] %w", err)
	}
	if err := validateAuditlogTargetS3Endpoint(this.Endpoint); err != nil {
		return fmt.Errorf("[endpoint] %w", err)
	}
	if err := validateAuditlogTargetS3ExpectedBucketOwner(this.ExpectedBucketOwner); err != nil {
		return fmt.Errorf("[expectedBucketOwner] %w", err)
	}
	if err := validateRequiredAuditlogTargetS3Template(this.AccessKeyId); err != nil {
		return fmt.Errorf("[accessKeyId] %w", err)
	}
	if err := validateRequiredAuditlogTargetS3Template(this.SecretAccessKey); err != nil {
		return fmt.Errorf("[secretAccessKey] %w", err)
	}
	usesDefaultAccessKey := this.AccessKeyId.IsEqualTo(DefaultAuditlogTargetS3AccessKeyId)
	usesDefaultSecretKey := this.SecretAccessKey.IsEqualTo(DefaultAuditlogTargetS3SecretAccessKey)
	if usesDefaultAccessKey != usesDefaultSecretKey {
		return fmt.Errorf("[accessKeyId] and [secretAccessKey] must either both use their defaults or both be configured")
	}
	if err := this.SessionToken.Validate(); err != nil {
		return fmt.Errorf("[sessionToken] %w", err)
	}
	return nil
}

func validateAuditlogTargetS3RegionTemplate(value template.String) error {
	if err := validateRequiredAuditlogTargetS3Template(value); err != nil {
		return err
	}
	if !value.IsHardCoded() {
		return nil
	}
	rendered, err := value.Render(nil)
	if err != nil {
		return err
	}
	return validateAuditlogTargetS3Region(strings.TrimSpace(rendered))
}

func validateRequiredAuditlogTargetS3Template(value template.String) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.IsZero() {
		return fmt.Errorf("required but absent")
	}
	return nil
}

type AuditlogTargetS3Values struct {
	Region          string
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

func (this AuditlogTargetS3) Render(data any) (result AuditlogTargetS3Values, err error) {
	if result.Region, err = this.Region.Render(data); err != nil {
		return result, fmt.Errorf("[region] cannot render: %w", err)
	}
	result.Region = strings.TrimSpace(result.Region)
	if err = validateAuditlogTargetS3Region(result.Region); err != nil {
		return result, fmt.Errorf("[region] %w", err)
	}
	if result.AccessKeyId, err = this.AccessKeyId.Render(data); err != nil {
		return result, fmt.Errorf("[accessKeyId] cannot render: %w", err)
	}
	if result.AccessKeyId == "" {
		return result, fmt.Errorf("[accessKeyId] required but absent after rendering")
	}
	if result.SecretAccessKey, err = this.SecretAccessKey.Render(data); err != nil {
		return result, fmt.Errorf("[secretAccessKey] cannot render: %w", err)
	}
	if result.SecretAccessKey == "" {
		return result, fmt.Errorf("[secretAccessKey] required but absent after rendering")
	}
	usesDefaultCredentials := this.AccessKeyId.IsEqualTo(DefaultAuditlogTargetS3AccessKeyId)
	usesDefaultSessionToken := this.usesDefaultSessionToken()
	if usesDefaultSessionToken && !usesDefaultCredentials {
		return result, nil
	}
	if result.SessionToken, err = this.SessionToken.Render(data); err != nil {
		return result, fmt.Errorf("[sessionToken] cannot render: %w", err)
	}
	return result, nil
}

func validateAuditlogTargetS3Bucket(value string) error {
	if len(value) < 3 || len(value) > 63 {
		return fmt.Errorf("must contain between 3 and 63 characters")
	}
	isAlphaNumeric := func(character byte) bool {
		return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
	}
	if !isAlphaNumeric(value[0]) || !isAlphaNumeric(value[len(value)-1]) {
		return fmt.Errorf("must start and end with a lowercase letter or digit")
	}
	for _, character := range []byte(value) {
		if isAlphaNumeric(character) || character == '-' || character == '.' {
			continue
		}
		return fmt.Errorf("contains illegal character %q", character)
	}
	if strings.Contains(value, "..") || strings.Contains(value, ".-") || strings.Contains(value, "-.") {
		return fmt.Errorf("contains adjacent periods or a period next to a hyphen")
	}
	if net.ParseIP(value) != nil {
		return fmt.Errorf("must not be formatted as an IP address")
	}
	for _, prefix := range []string{"xn--", "sthree-", "amzn_s3_demo_", "amzn-s3-demo-"} {
		if strings.HasPrefix(value, prefix) {
			return fmt.Errorf("uses reserved prefix %q", prefix)
		}
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", ".mrap", "--xa-s3", "--x-s3", "--table-s3", "-an"} {
		if strings.HasSuffix(value, suffix) {
			return fmt.Errorf("uses reserved suffix %q", suffix)
		}
	}
	return nil
}

func validateAuditlogTargetS3Region(value string) error {
	if value == "" {
		return fmt.Errorf("required but absent")
	}
	if len(value) > 63 {
		return fmt.Errorf("exceeds 63 bytes")
	}
	isAlphaNumeric := func(character byte) bool {
		return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
	}
	if !isAlphaNumeric(value[0]) || !isAlphaNumeric(value[len(value)-1]) {
		return fmt.Errorf("must start and end with a lowercase letter or digit")
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return fmt.Errorf("contains illegal character %q", character)
	}
	return nil
}

func validateAuditlogTargetS3Prefix(value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("is not valid UTF-8")
	}
	if len(value) > maximumAuditlogTargetS3PrefixLength {
		return fmt.Errorf("exceeds %d bytes", maximumAuditlogTargetS3PrefixLength)
	}
	if strings.ContainsRune(value, '\\') {
		return fmt.Errorf("contains a backslash")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("contains a control character")
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("contains an empty or relative path component")
		}
	}
	return nil
}

func validateAuditlogTargetS3Endpoint(value string) error {
	if value == "" {
		return nil
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
	if parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("must not contain a path")
	}
	return nil
}

func validateAuditlogTargetS3ExpectedBucketOwner(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 12 {
		return fmt.Errorf("must contain exactly 12 digits")
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return fmt.Errorf("contains non-decimal character %q", character)
		}
	}
	return nil
}

func (this *AuditlogTargetS3) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuditlogTargetS3, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "bucket", "region", "prefix", "endpoint", "pathStyle", "expectedBucketOwner", "accessKeyId", "secretAccessKey", "sessionToken"); err != nil {
			return err
		}
		type raw AuditlogTargetS3
		if err := node.Decode((*raw)(target)); err != nil {
			return err
		}
		target.sessionTokenDefault = true
		for index := 0; index < len(node.Content); index += 2 {
			if node.Content[index].Value == "sessionToken" && !auditlogTargetS3YAMLNodeIsNull(node.Content[index+1]) {
				target.sessionTokenDefault = false
				break
			}
		}
		return nil
	})
}

func auditlogTargetS3YAMLNodeIsNull(node *yaml.Node) bool {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node != nil && node.Tag == "!!null"
}

func (this AuditlogTargetS3) MarshalYAML() (any, error) {
	type encoded struct {
		Bucket              string          `yaml:"bucket"`
		Region              template.String `yaml:"region,omitempty"`
		Prefix              string          `yaml:"prefix,omitempty"`
		Endpoint            string          `yaml:"endpoint,omitempty"`
		PathStyle           bool            `yaml:"pathStyle,omitempty"`
		ExpectedBucketOwner string          `yaml:"expectedBucketOwner,omitempty"`
		AccessKeyId         template.String `yaml:"accessKeyId,omitempty"`
		SecretAccessKey     template.String `yaml:"secretAccessKey,omitempty"`
		SessionToken        *string         `yaml:"sessionToken,omitempty"`
	}
	result := encoded{
		Bucket: this.Bucket, Region: this.Region, Prefix: this.Prefix, Endpoint: this.Endpoint,
		PathStyle: this.PathStyle, ExpectedBucketOwner: this.ExpectedBucketOwner,
		AccessKeyId: this.AccessKeyId, SecretAccessKey: this.SecretAccessKey,
	}
	if !this.usesDefaultSessionToken() {
		sessionToken := this.SessionToken.String()
		result.SessionToken = &sessionToken
	}
	return result, nil
}

func (this AuditlogTargetS3) usesDefaultSessionToken() bool {
	return this.sessionTokenDefault && this.SessionToken.IsEqualTo(DefaultAuditlogTargetS3SessionToken)
}

func (this AuditlogTargetS3) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case AuditlogTargetS3:
		return this.isEqualTo(&value)
	case *AuditlogTargetS3:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}

func (this AuditlogTargetS3) isEqualTo(other *AuditlogTargetS3) bool {
	return this.Bucket == other.Bucket &&
		this.Region.IsEqualTo(other.Region) &&
		this.Prefix == other.Prefix &&
		this.Endpoint == other.Endpoint &&
		this.PathStyle == other.PathStyle &&
		this.ExpectedBucketOwner == other.ExpectedBucketOwner &&
		this.AccessKeyId.IsEqualTo(other.AccessKeyId) &&
		this.SecretAccessKey.IsEqualTo(other.SecretAccessKey) &&
		this.SessionToken.IsEqualTo(other.SessionToken) &&
		this.usesDefaultSessionToken() == other.usesDefaultSessionToken()
}

func (this AuditlogTargetS3) Types() []string {
	return []string{"s3"}
}

func (this AuditlogTargetS3) FeatureFlags() []string {
	return []string{"s3"}
}
