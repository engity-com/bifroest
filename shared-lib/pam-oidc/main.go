package main

/*
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"

import (
	oidc2 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/core"
	"github.com/engity/pam-oidc/pkg/errors"
	"github.com/engity/pam-oidc/pkg/pam"
	"golang.org/x/oauth2"
	"log/syslog"
)

func main() {
}

type executionContext struct {
	configuration core.Configuration
	user          string
}

func pamSmAuthenticate(ph *pam.Handle, flags pam.Flags, args ...string) pam.Result {
	eCtx, err := resolveExecutionContext(ph, flags, args...)
	if pamErr := pam.ForceAsError(err); pamErr != nil {
		pamErr.Result.Syslogf(ph, "%v", pamErr)
		return pamErr.Result
	}

	if pe := errors.ForceAs(authFlow(ph, eCtx)); pe != nil {
		pe.Syslog(ph)
		return pe.ResultCause
	}

	return pam.ResultSuccess
}

func pamSmSetcred(_ *pam.Handle, _ pam.Flags, _ ...string) pam.Result {
	return pam.ResultIgnore
}

func resolveExecutionContext(ph *pam.Handle, _ pam.Flags, args ...string) (*executionContext, error) {
	var ctx executionContext

	if err := ctx.configuration.LoadFromArgs(args...); err != nil {
		return nil, pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeConfiguration, "failed to parse config: %v", err)
	}

	u, err := ph.GetUser("")
	if err != nil {
		return nil, err
	}
	if len(u) == 0 {
		return nil, pam.ResultUserUnknown.Errorf(pam.ErrorCauseTypeUser, "empty user")
	}
	ctx.user = u

	return &ctx, nil
}

func authFlow(ph *pam.Handle, eCtx *executionContext) error {
	cord, err := core.NewCoordinator(&eCtx.configuration)
	if err != nil {
		return err
	}

	cord.OnDeviceAuthStarted = func(dar *oauth2.DeviceAuthResponse) error {
		if v := dar.VerificationURIComplete; v != "" {
			ph.UncheckedInfof("Open %s in your browser and approve the login request. Waiting for approval...", v)
		} else {
			ph.UncheckedInfof("Open %s in your browser and enter the code %s. Waiting for approval...", dar.VerificationURI, dar.UserCode)
		}
		return nil
	}

	cord.OnTokenReceived = func(token *oauth2.Token) error {
		ph.Syslogf(syslog.LOG_INFO, "Token:\n%s", common.ToDebugString(token))
		return nil
	}

	cord.OnUserInfoReceived = func(userInfo *oidc2.UserInfo) error {
		ph.Syslogf(syslog.LOG_INFO, "UserInfo:\n%s", common.ToDebugString(userInfo))
		return nil
	}

	if _, err := cord.Run(nil, eCtx.user); err != nil {
		return err
	}

	return nil
}
