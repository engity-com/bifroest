package oidc

import (
	"context"
	sdkerrors "errors"
	"github.com/coreos/go-oidc/v3/oidc"
	log "github.com/echocat/slf4g"
	"github.com/engity/pam-oidc/pkg/errors"
	"github.com/engity/pam-oidc/pkg/pam"
	"golang.org/x/oauth2"
	"io"
	"log/syslog"
	"net/http"
	"runtime"
	"time"
)

func init() {
	//http.DefaultTransport.(*http.Transport).MaxConnsPerHost = 1
}

type Client struct {
	oauth2Config oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

func logFoof(ph *pam.Handle, msg string, args ...any) {
	if ph != nil {
		ph.Syslogf(syslog.LOG_INFO, msg, args...)
	} else {
		log.Infof(msg, args...)
	}
}

func writeGoroutineStacks(w io.Writer) error {
	// We don't know how big the buffer needs to be to collect
	// all the goroutines. Start with 1 MB and try a few times, doubling each time.
	// Give up and use a truncated trace if 64 MB is not enough.
	buf := make([]byte, 1<<20)
	for i := 0; ; i++ {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		if len(buf) >= 64<<20 {
			// Filled 64 MB - stop there.
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	_, err := w.Write(buf)
	return err
}

func NewClient(ctx context.Context, conf Configuration, ph *pam.Handle) (*Client, error) {
	fail := func(err error) (*Client, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*Client, error) {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	logFoof(ph, "ON1")
	if ctx == nil {
		ctx = context.Background()
	}

	if conf == nil {
		return failf("nil configuration")
	}

	logFoof(ph, "ON2: %v", conf.GetOidcIssuer())
	timeout, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()
	req, nil := http.NewRequestWithContext(timeout, "GET", "https://echocat.org/robots.txt", nil)
	resp, _ := http.DefaultClient.Do(req)
	logFoof(ph, "ON2a")
	b, _ := io.ReadAll(resp.Body)
	logFoof(ph, "ON2b: %s", string(b))

	provider, err := oidc.NewProvider(ctx, conf.GetOidcIssuer())
	if err != nil {
		return failf("cannot evaluate OIDC issuer %q: %w", conf.GetOidcIssuer(), err)
	}

	logFoof(ph, "ON3")
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

	if ctx == nil {
		ctx = context.Background()
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

	if ctx == nil {
		ctx = context.Background()
	}

	if using == nil || using.DeviceCode == "" {
		return failf(errors.TypeSystem, "no device auth response provided")
	}

	response, err := this.oauth2Config.DeviceAccessToken(ctx, using, oauth2.SetAuthURLParam("client_secret", this.oauth2Config.ClientSecret))
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

func (this *Client) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
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
