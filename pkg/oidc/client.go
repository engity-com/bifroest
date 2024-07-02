package oidc

import (
	"context"
	sdkerrors "errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/engity/pam-oidc/pkg/errors"
)

type Client struct {
	oauth2Config oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

func NewClient(ctx context.Context, conf Configuration) (*Client, error) {
	fail := func(err error) (*Client, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*Client, error) {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	provider, err := oidc.NewProvider(ctx, conf.GetOidcIssuer())
	if err != nil {
		return failf("cannot evaluate OIDC issuer %q: %w", conf.GetOidcIssuer(), err)
	}

	result := Client{
		oauth2Config: oauth2.Config{
			ClientID:     conf.GetOidcClientId(),
			ClientSecret: conf.GetOidcClientSecret(),
			Endpoint:     provider.Endpoint(),
			Scopes:       conf.GetOidcScopes(),
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: conf.GetOidcClientId(),
		}),
	}

	return &result, nil
}

func (this *Client) InitiateDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	fail := func(err error) (*oauth2.DeviceAuthResponse, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*oauth2.DeviceAuthResponse, error) {
		return fail(errors.Newf(errors.TypeNetwork, msg, args...))
	}

	response, err := this.oauth2Config.DeviceAuth(ctx)
	if err != nil {
		return failf("cannot initiate successful device auth: %w", err)
	}

	return response, err
}

func (this *Client) RetrieveDeviceAuthToken(ctx context.Context, using *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	fail := func(err error) (*oauth2.Token, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oauth2.Token, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if using == nil || using.DeviceCode == "" {
		return failf(errors.TypeSystem, "no device auth response provided")
	}

	response, err := this.oauth2Config.DeviceAccessToken(ctx, using)
	if sdkerrors.Is(err, context.DeadlineExceeded) {
		return failf(errors.TypeUser, "authorize of device timed out")
	}
	if err != nil {
		return failf(errors.TypeNetwork, "cannot authorize device: %w", err)
	}

	return response, err
}

func (this *Client) VerifyToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	fail := func(err error) (*oidc.IDToken, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oidc.IDToken, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if token == nil || token.AccessToken == "" {
		return failf(errors.TypeSystem, "no token provided")
	}

	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		return failf(errors.TypePermission, "token does not contain id_token")
	}

	idToken, err := this.verifier.Verify(ctx, rawIdToken)
	if err != nil {
		return failf(errors.TypePermission, "cannot verify ID token: %w", err)
	}

	return idToken, nil
}

func (this *Client) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
	fail := func(err error) (*oidc.UserInfo, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oidc.UserInfo, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	result, err := this.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return failf(errors.TypePermission, "%w", err)
	}

	return result, nil
}
