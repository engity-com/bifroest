package core

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/errors"
)

func NewConfiguration() (*Configuration, error) {
	o, err := NewConfigurationOidc()
	if err != nil {
		return nil, err
	}
	u, err := NewConfigurationUser()
	if err != nil {
		return nil, err
	}
	return &Configuration{
		Oidc:    *o,
		User:    *u,
		Timeout: time.Minute * 5,
	}, nil
}

type Configuration struct {
	Oidc ConfigurationOidc `yaml:"oidc,omitempty"`
	User ConfigurationUser `yaml:"user,omitempty"`

	Timeout time.Duration `yaml:"timeout,omitempty"`
}

func (this Configuration) GetOidcIssuer() string {
	return strings.Clone(this.Oidc.Issuer)
}

func (this Configuration) GetOidcClientId() string {
	return strings.Clone(this.Oidc.ClientId)
}

func (this Configuration) GetOidcClientSecret() string {
	return strings.Clone(this.Oidc.ClientSecret)
}

func (this Configuration) GetTimeout() time.Duration {
	return this.Timeout
}

func (this Configuration) GetOidcScopes() []string {
	return slices.Clone(this.Oidc.Scopes)
}

func (this Configuration) ToContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), this.Timeout)
}

func (this Configuration) Validate(key common.StructuredKey) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if this.Timeout == 0 {
		return failf("required option %v missing", key.Child("timeout"))
	}
	if this.Timeout < 0 {
		return failf("option %v negative but has to be always positive", key.Child("timeout"))
	}

	if err := this.Oidc.Validate(key.Child("oidc")); err != nil {
		return fail(err)
	}
	if err := this.User.Validate(key.Child("user")); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Configuration) LoadFromFile(fn string) error {
	f, err := os.Open(fn)
	if os.IsNotExist(err) {
		return errors.Newf(errors.TypeConfig, "configuration file %q does not exist", fn)
	}
	if err != nil {
		return errors.Newf(errors.TypeConfig, "cannot open configuration file %q: %w", fn, err)
	}
	defer func() { _ = f.Close() }()

	return this.LoadFromYaml(f, fn)
}

func (this *Configuration) LoadFromYaml(reader io.Reader, fn string) error {
	if fn == "" {
		fn = "<anonymous>"
	}

	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	buf, err := NewConfiguration()
	if err != nil {
		return err
	}
	if err := decoder.Decode(&buf); err != nil {
		return errors.Newf(errors.TypeConfig, "cannot parse configuration file %q: %w", fn, err)
	}

	if err := buf.Validate(nil); err != nil {
		return errors.Newf(errors.TypeConfig, "configuration file %q contains problems: %w", fn, err)
	}

	*this = *buf
	return nil
}

type ConfigurationProvider interface {
	Get(ConfigurationKey) (*Configuration, error)
	GetKeys() ([]ConfigurationKey, error)
}
