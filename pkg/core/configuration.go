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

	"github.com/coreos/go-oidc/v3/oidc"

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
	return &Configuration{
		Timeout: time.Minute * 10,
		Scopes:  []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}

type Configuration struct {
	// Issuer is the OpenID Connect issuer
	Issuer       string
	ClientId     string
	ClientSecret string
	Timeout      time.Duration
	Scopes       []string

	// UserTemplate is a template that, when rendered with the JWT claims, should
	// match the user being authenticated.
	UserTemplate string
	// GroupsClaimKey is the name of the key within the token claims that
	// specifies which groups a user is a member of.
	GroupsClaimKey string
	// AuthorizedGroups is a list of groups required for authentication to pass.
	// A user must be a member of at least one of the groups in the list, if
	// specified.
	AuthorizedGroups []string
	// RequireACRs is a list of required ACRs required for authentication to pass.
	// one of the acr values must be present in the claims.
	RequireACRs []string
}

func (this Configuration) GetIssuer() string {
	return strings.Clone(this.Issuer)
}

func (this Configuration) GetClientId() string {
	return strings.Clone(this.ClientId)
}

func (this Configuration) GetClientSecret() string {
	return strings.Clone(this.ClientSecret)
}

func (this Configuration) GetTimeout() time.Duration {
	return this.Timeout
}

func (this Configuration) GetScopes() []string {
	return slices.Clone(this.Scopes)
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
