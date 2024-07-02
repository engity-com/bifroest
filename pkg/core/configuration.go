package core

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>

char* argv_i(const char **argv, int i);
*/
import "C"
import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/engity/pam-oidc/pkg/errors"
)

const (
	ConfigKeyIssuer       = "issuer"
	ConfigKeyClientId     = "client_id"
	ConfigKeyClientSecret = "client_secret"
	ConfigKeyTimeout      = "timeout"
	ConfigKeyScopes       = "scopes"

	ConfigKeyUserTemplate     = "user_template"
	ConfigKeyGroupsClaim      = "groups_claim"
	ConfigKeyAuthorizedGroups = "authorized_groups"
	ConfigKeyRequireAcr       = "require_acr"
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
		Timeout: time.Minute * 10,
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

func (this Configuration) NewContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), this.Timeout)
}

func (this Configuration) Validate() error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if this.Issuer == "" {
		return failf("required PAM option %s missing", ConfigKeyIssuer)
	}
	if this.ClientId == "" {
		return failf("required PAM option %s missing", ConfigKeyClientId)
	}
	if this.ClientSecret == "" {
		return failf("required PAM option %s missing", ConfigKeyClientSecret)
	}
	if this.Timeout == 0 {
		return failf("required PAM option %s missing", ConfigKeyTimeout)
	}
	if this.Timeout < 0 {
		return failf("PAM option %s negative but has to be always positive", ConfigKeyTimeout)
	}
	if len(this.Scopes) == 0 {
		return failf("required PAM option %s missing", ConfigKeyScopes)
	}

	return nil
}

func (this *Configuration) ParseArgs(args []string) error {
	buf, err := NewConfiguration()
	if err != nil {
		return err
	}

	for _, arg := range args {
		if err := buf.ParseArg(arg); err != nil {
			return err
		}
	}

	*this = *buf

	return nil
}

func (this *Configuration) ParseArg(arg string) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return failf("malformed arg: %v", arg)
	}
	key := parts[0]
	value := parts[1]

	switch key {
	case ConfigKeyIssuer:
		this.Issuer = value
	case ConfigKeyClientId:
		this.ClientId = value
	case ConfigKeyClientSecret:
		this.ClientSecret = value
	case ConfigKeyTimeout:
		v, err := time.ParseDuration(value)
		if err != nil {
			return failf("malformed arg: %v", arg)
		}
		this.Timeout = v
	case ConfigKeyScopes:
		scopes := strings.Split(value, ",")
		for i, v := range scopes {
			scopes[i] = strings.TrimSpace(v)
		}
		this.Scopes = slices.DeleteFunc(scopes, func(s string) bool { return len(s) == 0 })
	case ConfigKeyUserTemplate:
		this.UserTemplate = value
	case ConfigKeyGroupsClaim:
		this.GroupsClaimKey = value
	case ConfigKeyAuthorizedGroups:
		this.AuthorizedGroups = strings.Split(value, ",")
	case ConfigKeyRequireAcr:
		this.RequireACRs = strings.Split(value, ",")
	default:
		return failf("unknown option: %v", key)
	}
	return nil
}
