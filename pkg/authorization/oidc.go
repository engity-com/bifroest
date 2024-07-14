package authorization

import (
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity-com/yasshd/pkg/configuration"
	"golang.org/x/oauth2"
)

type OidcAuth struct {
	Token    OidcToken
	IdToken  OidcIdToken
	UserInfo OidcUserInfo
	flow     configuration.FlowName
}

func (this *OidcAuth) IsAuthorized() bool {
	return true
}

func (this *OidcAuth) Flow() configuration.FlowName {
	return this.flow
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
