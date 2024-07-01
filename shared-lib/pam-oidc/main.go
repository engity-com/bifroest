package main

/*
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
*/
import "C"

import (
	"encoding/json"
	"github.com/engity/pam-oidc/pkg/core"
	"github.com/engity/pam-oidc/pkg/errors"
	"github.com/engity/pam-oidc/pkg/oidc"
	"github.com/engity/pam-oidc/pkg/user"
	"log/syslog"
	"strings"

	"github.com/engity/pam-oidc/pkg/pam"
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

	if err := ctx.configuration.ParseArgs(args); err != nil {
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
	ctx, cancelFunc := eCtx.configuration.NewContext()
	defer cancelFunc()

	oidcCl, err := oidc.NewClient(ctx, eCtx.configuration)
	if err != nil {
		return err
	}

	dar, err := oidcCl.InitiateDeviceAuth(ctx)
	if err != nil {
		return err
	}

	if v := dar.VerificationURIComplete; v != "" {
		ph.UncheckedInfof("Open %s in your browser and approve the login request. Waiting for approval...", v)
	} else {
		ph.UncheckedInfof("Open %s in your browser and enter the code %s. Waiting for approval...", dar.VerificationURI, dar.UserCode)
	}

	token, err := oidcCl.RetrieveDeviceAuthToken(ctx, dar)
	if err != nil {
		return err
	}

	var bufToken strings.Builder
	tokenEncoder := json.NewEncoder(&bufToken)
	tokenEncoder.SetIndent("", "   ")
	_ = tokenEncoder.Encode(token)

	idToken, err := oidcCl.VerifyToken(ctx, token)
	if err != nil {
		return err
	}

	var bufIdToken strings.Builder
	idTokenEncoder := json.NewEncoder(&bufIdToken)
	idTokenEncoder.SetIndent("", "   ")
	_ = idTokenEncoder.Encode(idToken)

	userInfo, err := oidcCl.GetUserInfo(ctx, token)
	if err != nil {
		return err
	}

	var bufUserInfo strings.Builder
	userInfoEncoder := json.NewEncoder(&bufUserInfo)
	userInfoEncoder.SetIndent("", "   ")
	_ = userInfoEncoder.Encode(userInfo)

	ph.Syslogf(syslog.LOG_INFO, "Token: %s \n\n IdToken: %s \n\n UserInfo: %s", bufToken.String(), bufIdToken.String(), bufUserInfo.String())

	toUser := "foo"

	if err := ph.SetUser(toUser); err != nil {
		ph.Syslogf(syslog.LOG_ERR, "cannot set user to %q: %v", toUser, err)
	}

	u, err := user.Lookup(toUser)
	if err != nil {
		ph.Syslogf(syslog.LOG_ERR, "cannot lookup user %q: %v", toUser, err)
	}
	if u != nil {
		ph.Syslogf(syslog.LOG_INFO, "user: %+v", u)
		g, err := u.GetGroup()
		if err != nil {
			ph.Syslogf(syslog.LOG_ERR, "cannot get group of %v: %v", u, err)
		} else {
			ph.Syslogf(syslog.LOG_INFO, "user's group: %+v", g)
		}
		gs, err := u.GetGroups()
		if err != nil {
			ph.Syslogf(syslog.LOG_ERR, "cannot get groups of %v: %v", u, err)
		} else {
			for i, g := range gs {
				ph.Syslogf(syslog.LOG_INFO, "user's group #%d: %+v", i, g)
			}
		}
	}

	return nil
}
