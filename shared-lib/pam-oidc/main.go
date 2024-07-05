package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"

import (
	"context"
	oidc2 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/core"
	"github.com/engity/pam-oidc/pkg/pam"
	"github.com/pardot/oidc/discovery"
	"golang.org/x/oauth2"

	"io"
	"log/syslog"
	"net/http"
	"strings"
	"time"
)

func main() {
}

func pamSmAuthenticate(ph *pam.Handle, flags pam.Flags, args ...string) pam.Result {
	ph.UncheckedInfof("Hey you!")

	ph.Syslogf(syslog.LOG_INFO, "1")
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	ph.Syslogf(syslog.LOG_INFO, "1a")
	_, _ = discovery.NewClient(ctx, "https://login.microsoftonline.com/89e12624-e5c9-43e5-b8a8-a76b7349cdaf/v2.0", discovery.WithHTTPClient(&http.Client{
		Transport: transport,
	}))
	ph.Syslogf(syslog.LOG_INFO, "1b")
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://echocat.org/robots.txt", nil)
	ph.Syslogf(syslog.LOG_INFO, "1c")
	resp, _ := http.DefaultClient.Do(req)
	ph.Syslogf(syslog.LOG_INFO, "1d")
	b, _ := io.ReadAll(resp.Body)
	ph.Syslogf(syslog.LOG_INFO, "1e: %q", string(b))

	fail := func(err error) pam.Result {
		if pErr := pam.AsError(err); pErr != nil {
			ph.Syslogf(pErr.Result.SyslogPriority(), "%v", pErr)
			return pErr.Result
		}
		ph.Syslogf(syslog.LOG_ERR, "%v", err)
		return pam.ResultSystemErr
	}
	failf := func(pr pam.Result, pect pam.ErrorCauseType, cause error, message string, args ...any) pam.Result {
		if cause != nil {
			message = message + ": %w"
			args = append(args, cause)
		}
		return fail(pr.Errorf(pect, message, args...))
	}

	conf, un, err := resolveEnv(ph, flags, args...)
	if err != nil {
		return fail(err)
	}

	cord, err := core.NewCoordinator(conf)
	if err != nil {
		return fail(err)
	}

	cord.OnDeviceAuthStarted = func(dar *oauth2.DeviceAuthResponse) error {
		ph.Syslogf(syslog.LOG_INFO, "device authorization flow for remote user %q via issuser %s started...", un, conf.Oidc.Issuer)
		if v := dar.VerificationURIComplete; v != "" {
			ph.UncheckedInfof("Open %s in your browser and approve the login request. Waiting for approval...", v)
		} else {
			ph.UncheckedInfof("Open %s in your browser and enter the code %s. Waiting for approval...", dar.VerificationURI, dar.UserCode)
		}
		return nil
	}
	cord.OnTokenReceived = func(v *oauth2.Token) error {
		ph.Syslogf(syslog.LOG_DEBUG, "token for remote use %q received: %s", un, common.ToDebugString(false, v))
		return nil
	}
	cord.OnIdTokenReceived = func(v *oidc2.IDToken) error {
		claims := map[string]any{}
		if err := v.Claims(&claims); err != nil {
			return err
		}
		ph.Syslogf(syslog.LOG_DEBUG, "id token for remote use %q received: %s", un, common.ToDebugString(false, claims))
		return nil
	}
	cord.OnUserInfoReceived = func(v *oidc2.UserInfo) error {
		claims := map[string]any{}
		if err := v.Claims(&claims); err != nil {
			return err
		}
		ph.Syslogf(syslog.LOG_DEBUG, "user info for remote use %q received: %s", un, common.ToDebugString(false, claims))
		return nil
	}

	u, result, err := cord.Run(nil, un, ph)
	if err != nil {
		return fail(err)
	}

	switch result {
	case core.CoordinatorRunResultSuccess:
		if err := ph.SetUser(u.Name); err != nil {
			return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "cannot switch for remote user %q to local user %v", un, u)
		}
		ph.Syslogf(syslog.LOG_INFO, "remote user %q was successfully authorized as local user %v", un, u)
		return pam.ResultSuccess
	case core.CoordinatorRunResultRequestingNameForbidden:
		return failf(pam.ResultUserUnknown, pam.ErrorCauseTypeUser, err, "remote user %q is forbidden by configuration", un)
	case core.CoordinatorRunResultOidcAuthorizeTimeout:
		return failf(pam.ResultIgnore, pam.ErrorCauseTypeUser, err, "the authorization request was not completed within timeout for user %q using issuer %s", un, conf.Oidc.Issuer)
	case core.CoordinatorRunResultOidcAuthorizeFailed:
		return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "was not able authorize client for user %q using issuer %s", un, conf.Oidc.Issuer)
	case core.CoordinatorRunResultRequirementResolutionFailed:
		return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "was not able to resolve user requirement for remote user %q / local user %v of issuer %s", un, u, conf.Oidc.Issuer)
	case core.CoordinatorRunResultLoginAllowedResolutionFailed:
		return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "was not able to resolve if remote user %q / local user %v is allowed to login of issuer %s", un, u, conf.Oidc.Issuer)
	case core.CoordinatorRunResultLoginForbidden:
		return failf(pam.ResultCredentialsInsufficient, pam.ErrorCauseTypeUser, err, "remote user %q / local user %v of issuer %s is not allowed to login", un, u, conf.Oidc.Issuer)
	case core.CoordinatorRunResultUserEnsuringFailed:
		return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "was not able to ensure remote user %q / local user %v of issuer %s", un, u, conf.Oidc.Issuer)
	case core.CoordinatorRunResultNoSuchUser:
		return failf(pam.ResultUserUnknown, pam.ErrorCauseTypeUser, err, "remote user %q is unknown", un)
	default:
		return failf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, err, "unknown error for remote user %q", un)
	}
}

func pamSmSetcred(_ *pam.Handle, _ pam.Flags, _ ...string) pam.Result {
	return pam.ResultIgnore
}

func resolveEnv(ph *pam.Handle, _ pam.Flags, args ...string) (*core.Configuration, string, error) {
	configFn := "/etc/pam-oidc.yaml"
	if nArgs := len(args); nArgs == 1 {
		configFn = args[0]
	} else if nArgs > 0 {
		return nil, "", pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeConfiguration, "too many args provided - expect 0 or 1; but got %d: %s", nArgs, strings.Join(args, " "))
	}
	var conf core.Configuration
	if err := conf.LoadFromFile(configFn); err != nil {
		return nil, "", pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeConfiguration, "failed to parse config: %v", err)
	}

	un, err := ph.GetUser("")
	if err != nil {
		return nil, "", err
	}
	if len(un) == 0 {
		return nil, "", pam.ResultUserUnknown.Errorf(pam.ErrorCauseTypeUser, "empty user")
	}

	return &conf, un, nil
}
