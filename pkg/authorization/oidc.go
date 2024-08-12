package authorization

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"golang.org/x/oauth2"
)

type OidcAuth struct {
	Token    OidcToken
	IdToken  OidcIdToken
	UserInfo OidcUserInfo
	remote   common.Remote
	flow     configuration.FlowName
}

func (this *OidcAuth) Remote() common.Remote {
	return this.remote
}

func (this *OidcAuth) IsAuthorized() bool {
	return true
}

func (this *OidcAuth) EnvVars() sys.EnvVars {
	return nil
}

func (this *OidcAuth) Flow() configuration.FlowName {
	return this.flow
}

func (this *OidcAuth) MarshalToken() ([]byte, error) {
	return json.Marshal(newOidcToken(this.Token.Token))
}

type OidcToken struct {
	*oauth2.Token
}

func (this *OidcToken) SetRaw(v *oauth2.Token) error {
	*this = OidcToken{v}
	return nil
}

type OidcIdToken struct {
	*oidc.IDToken
	Claims map[string]any
}

func (this *OidcIdToken) SetRaw(v *oidc.IDToken) error {
	var claims map[string]any
	if v != nil {
		if err := v.Claims(&claims); err != nil {
			return fmt.Errorf("cannot decode claims of idToken: %w", err)
		}
	}
	*this = OidcIdToken{v, claims}
	return nil
}

type OidcUserInfo struct {
	*oidc.UserInfo
	Claims map[string]any
}

func (this *OidcUserInfo) SetRaw(v *oidc.UserInfo) error {
	var claims map[string]any
	if v != nil {
		if err := v.Claims(&claims); err != nil {
			return fmt.Errorf("cannot decode claims of userInfo: %w", err)
		}
	}
	*this = OidcUserInfo{v, claims}
	return nil
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
