package core

import (
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity/pam-oidc/pkg/user"
	"golang.org/x/oauth2"
)

type RenderContextOidcResolved struct {
	Oidc RenderContextOidc
}

type RenderContextRequirementResolved struct {
	*RenderContextOidcResolved
	User user.Requirement
}

type RenderContextOidc struct {
	Token    RenderContextOidcToken
	IdToken  RenderContextOidcIdToken
	UserInfo RenderContextOidcUserInfo
}

type RenderContextOidcToken struct {
	*oauth2.Token
}

func (this *RenderContextOidcToken) SetRaw(v *oauth2.Token) error {
	*this = RenderContextOidcToken{v}
	return nil
}

type RenderContextOidcIdToken struct {
	*oidc.IDToken
	Claims map[string]any
}

func (this *RenderContextOidcIdToken) SetRaw(v *oidc.IDToken) error {
	var claims map[string]any
	if v != nil {
		if err := v.Claims(&claims); err != nil {
			return fmt.Errorf("cannot decode claims of idToken: %w", err)
		}
	}
	*this = RenderContextOidcIdToken{v, claims}
	return nil
}

type RenderContextOidcUserInfo struct {
	*oidc.UserInfo
	Claims map[string]any
}

func (this *RenderContextOidcUserInfo) SetRaw(v *oidc.UserInfo) error {
	var claims map[string]any
	if v != nil {
		if err := v.Claims(&claims); err != nil {
			return fmt.Errorf("cannot decode claims of userInfo: %w", err)
		}
	}
	*this = RenderContextOidcUserInfo{v, claims}
	return nil
}
