package authorization

import (
	"context"
	"fmt"
	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"sync"
)

type oidc struct {
	token             OidcToken
	idToken           OidcIdToken
	userInfo          OidcUserInfo
	remote            common.Remote
	flow              configuration.FlowName
	session           session.Session
	sessionsPublicKey ssh.PublicKey
}

func (this *oidc) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		switch name {
		case "token":
			return &this.token, true, nil
		case "idToken":
			return &this.idToken, true, nil
		case "userInfo":
			return &this.userInfo, true, nil
		default:
			return nil, false, fmt.Errorf("unknown field %q", name)
		}
	})
}

func (this *oidc) Remote() common.Remote {
	return this.remote
}

func (this *oidc) IsAuthorized() bool {
	return true
}

func (this *oidc) EnvVars() sys.EnvVars {
	return nil
}

func (this *oidc) Flow() configuration.FlowName {
	return this.flow
}

func (this *oidc) FindSession() session.Session {
	return this.session
}

func (this *oidc) FindSessionsPublicKey() ssh.PublicKey {
	return this.sessionsPublicKey
}

func (this *oidc) Dispose(ctx context.Context) (bool, error) {
	sess := this.session
	if sess == nil {
		return false, nil
	}

	// Delete myself from my session.
	if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
		return false, err
	}

	return true, nil
}

type OidcToken struct {
	*oauth2.Token
}

func (this OidcToken) GetField(name string) (any, bool) {
	t := this.Token
	if t == nil {
		return nil, true
	}
	switch name {
	case "accessToken", "access_token":
		return t.AccessToken, true
	case "tokenType", "token_type":
		return t.TokenType, true
	case "refreshToken", "refresh_token":
		return t.RefreshToken, true
	case "expiry":
		return t.Expiry, true
	default:
		return t.Extra(name), true
	}
}

func (this *OidcToken) SetRaw(v *oauth2.Token) error {
	*this = OidcToken{v}
	return nil
}

type OidcIdToken struct {
	*coidc.IDToken
	claims map[string]any
	init   sync.Once
}

func (this *OidcIdToken) GetField(name string) (_ any, _ bool, err error) {
	t := this.IDToken
	if t == nil {
		return nil, true, nil
	}

	switch name {
	case "issuer":
		return t.Issuer, true, nil
	case "audience":
		return t.Audience, true, nil
	case "subject":
		return t.Subject, true, nil
	case "expiry":
		return t.Expiry, true, nil
	case "issuedAt":
		return t.IssuedAt, true, nil
	case "nonce":
		return t.Nonce, true, nil
	case "accessTokenHash":
		return t.AccessTokenHash, true, nil
	default:
		this.init.Do(func() {
			err = t.Claims(&this.claims)
		})
		if err != nil {
			return nil, false, err
		}
		return this.claims[name], true, nil
	}
}

type OidcUserInfo struct {
	*coidc.UserInfo
	claims map[string]any
	init   sync.Once
}

func (this *OidcUserInfo) GetField(name string) (_ any, _ bool, err error) {
	t := this.UserInfo
	if t == nil {
		return nil, true, nil
	}

	switch name {
	case "subject":
		return t.Subject, true, nil
	case "profile":
		return t.Profile, true, nil
	case "email":
		return t.Email, true, nil
	case "emailVerified":
		return t.EmailVerified, true, nil
	default:
		this.init.Do(func() {
			err = t.Claims(&this.claims)
		})
		if err != nil {
			return nil, false, err
		}
		return this.claims[name], true, nil
	}
}

func newOidcToken(in *oauth2.Token) oidcToken {
	result := oidcToken{Token: in}
	if in != nil {
		if v, ok := in.Extra("id_token").(string); ok {
			result.IdToken = v
		}
	}
	return result
}

type oidcToken struct {
	*oauth2.Token
	IdToken string `json:"id_token,omitempty"`
}
