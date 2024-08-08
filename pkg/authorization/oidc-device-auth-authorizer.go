package authorization

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"golang.org/x/oauth2"
)

type OidcDeviceAuthAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationOidcDeviceAuth

	oauth2Config oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

func NewOidcDeviceAuth(ctx context.Context, flow configuration.FlowName, conf *configuration.AuthorizationOidcDeviceAuth) (*OidcDeviceAuthAuthorizer, error) {
	fail := func(err error) (*OidcDeviceAuthAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*OidcDeviceAuthAuthorizer, error) {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if conf == nil {
		return failf("nil configuration")
	}

	provider, err := oidc.NewProvider(ctx, conf.Issuer)
	if err != nil {
		return failf("cannot evaluate OIDC issuer %q: %w", conf.Issuer, err)
	}

	result := OidcDeviceAuthAuthorizer{
		flow: flow,
		conf: conf,

		oauth2Config: oauth2.Config{
			ClientID:     conf.ClientId,
			ClientSecret: conf.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       conf.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: conf.ClientId,
		}),
	}

	return &result, nil
}

func (this *OidcDeviceAuthAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize via oidc device auth: %w", err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	ctx := req.Context()

	dar, err := this.InitiateDeviceAuth(ctx)
	if err != nil {
		return fail(err)
	}

	var verificationMessage string
	if v := dar.VerificationURIComplete; v != "" {
		verificationMessage = fmt.Sprintf("Open the following URL in your browser to login: %s", v)
	} else {
		verificationMessage = fmt.Sprintf("Open the following URL in your browser and provide the code %q to login: %s", dar.UserCode, dar.VerificationURI)
	}
	if err := req.SendInfo(verificationMessage); err != nil {
		return failf("cannot send device code request to user: %w", err)
	}

	auth := OidcAuth{
		flow: this.flow,
	}

	token, err := this.RetrieveDeviceAuthToken(ctx, dar)
	if err != nil {
		return fail(err)
	}
	if err := auth.Token.SetRaw(token); err != nil {
		return failf("cannot store token at response: %w", err)
	}

	req.Logger().Debug("token received")

	if this.conf.RetrieveIdToken {
		idToken, err := this.VerifyToken(ctx, token)
		if err != nil {
			return fail(err)
		}

		if err := auth.IdToken.SetRaw(idToken); err != nil {
			return failf("cannot store id token at response: %w", err)
		}

		req.Logger().With("idToken", auth.IdToken).Debug("id token received")
	}

	if this.conf.RetrieveUserInfo {
		userInfo, err := this.GetUserInfo(ctx, token)
		if err != nil {
			return fail(err)
		}

		if err := auth.UserInfo.SetRaw(userInfo); err != nil {
			return failf("cannot store user info at response: %w", err)
		}

		req.Logger().With("userInfo", auth.UserInfo).Debug("user info received")
	}

	if ok, err := req.Validate(&auth); err != nil {
		return fail(err)
	} else if !ok {
		return Forbidden(), nil
	}

	return &auth, nil
}

func (this *OidcDeviceAuthAuthorizer) InitiateDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	fail := func(err error) (*oauth2.DeviceAuthResponse, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*oauth2.DeviceAuthResponse, error) {
		return fail(errors.Newf(errors.TypeNetwork, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	response, err := this.oauth2Config.DeviceAuth(ctx)
	if err != nil {
		return failf("cannot initiate successful device auth: %w", err)
	}

	return response, err
}

func (this *OidcDeviceAuthAuthorizer) RetrieveDeviceAuthToken(ctx context.Context, using *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	fail := func(err error) (*oauth2.Token, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oauth2.Token, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if using == nil || using.DeviceCode == "" {
		return failf(errors.TypeSystem, "no device auth response provided")
	}

	response, err := this.oauth2Config.DeviceAccessToken(ctx, using, oauth2.SetAuthURLParam("client_secret", this.oauth2Config.ClientSecret))
	if errors.Is(err, context.DeadlineExceeded) {
		return failf(errors.TypeUser, "authorize of device timed out")
	}
	if errors.Is(err, context.Canceled) {
		return failf(errors.TypeUser, "authorize cancelled by user")
	}
	var oaErr *oauth2.RetrieveError
	if errors.As(err, &oaErr) && oaErr.ErrorCode == "expired_token" {
		return failf(errors.TypeUser, "authorize of device timed out by IdP")
	}
	if err != nil {
		return failf(errors.TypeNetwork, "cannot authorize device: %w", err)
	}

	return response, err
}

func (this *OidcDeviceAuthAuthorizer) VerifyToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	fail := func(err error) (*oidc.IDToken, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oidc.IDToken, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
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

func (this *OidcDeviceAuthAuthorizer) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
	fail := func(err error) (*oidc.UserInfo, error) {
		return nil, err
	}
	failf := func(pt errors.Type, msg string, args ...any) (*oidc.UserInfo, error) {
		return fail(errors.Newf(pt, msg, args...))
	}

	if ctx == nil {
		ctx = context.Background()
	}

	result, err := this.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return failf(errors.TypePermission, "%w", err)
	}

	return result, nil
}

func (this *OidcDeviceAuthAuthorizer) AuthorizePublicKey(PublicKeyRequest) (Authorization, error) {
	return Forbidden(), nil
}

func (this *OidcDeviceAuthAuthorizer) AuthorizePassword(PasswordRequest) (Authorization, error) {
	return Forbidden(), nil
}

func (this *OidcDeviceAuthAuthorizer) Close() error {
	return nil
}
