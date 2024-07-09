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
	"fmt"
	"github.com/echocat/slf4g/level"
	"github.com/engity/pam-oidc/pkg/core"
	"github.com/engity/pam-oidc/pkg/pam"
	"log/syslog"
	"syscall"
)

func main() {}

func pamSmAuthenticate(ph *pam.Handle, flags pam.Flags, args ...string) pam.Result {
	ph.UncheckedInfof("Hey yousel!\n")

	ph.Syslogf(syslog.LOG_DEBUG, "1 %+v - %+v", flags, args)

	fail := func(err error) pam.Result {
		if pErr := pam.AsError(err); pErr != nil {
			ph.Syslogf(pErr.Result.SyslogPriority(), "%v", pErr)
			return pErr.Result
		} else {
			ph.Syslogf(syslog.LOG_ERR, "%v", err)
			return pam.ResultSystemErr
		}
	}

	socketPath, confKey, requestedUsername, err := resolveEnv(ph, flags, args...)
	if err != nil {
		return fail(err)
	}
	ph.Syslogf(syslog.LOG_DEBUG, "2")

	fd, err := openSocket(socketPath)
	if err != nil {
		return fail(err)
	}
	defer func() {
		_ = fd.Close()
	}()
	ph.Syslogf(syslog.LOG_DEBUG, "3")

	if err := core.WriteCommandHeader(requestedUsername, confKey, "pam_oidc", fd); err != nil {
		return fail(err)
	}

	ph.Syslogf(syslog.LOG_DEBUG, "4")

	cr := newCommandReceiver(ph, requestedUsername)

	ph.Syslogf(syslog.LOG_DEBUG, "5")

	if _, err := cr.Run(fd); err != nil {
		return fail(err)
	}

	ph.Syslogf(syslog.LOG_DEBUG, "6")

	return pam.ResultSuccess
}

func newCommandReceiver(ph *pam.Handle, requestedUsername string) *core.CommandReceiver {
	return &core.CommandReceiver{
		OnLog: func(l level.Level, message string) error {
			var prio syslog.Priority
			if l >= level.Fatal {
				prio = syslog.LOG_EMERG
			} else if l >= level.Error {
				prio = syslog.LOG_ERR
			} else if l >= level.Warn {
				prio = syslog.LOG_WARNING
			} else if l >= level.Info {
				prio = syslog.LOG_INFO
			} else {
				prio = syslog.LOG_DEBUG
			}
			ph.Syslogf(prio, message)
			return nil
		},

		OnInfo: func(message string) error {
			return ph.Infof(message)
		},

		OnSuccessResult: func(r core.Result, localUser string, localUid uint64, localGroup string, localGid uint64) (core.Result, error) {
			if err := ph.SetUser(localUser); err != nil {
				return core.ResultSystemErr, pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeSystem, "cannot switch for remote user %q to local user %v: %w", requestedUsername, localUser, err)
			}
			ph.Syslogf(syslog.LOG_INFO, "remote user %q was successfully authorized as local user %d(%s):%d(%s)", requestedUsername, localUid, localUser, localGid, localGroup)
			return r, nil
		},

		OnFailedResult: func(r core.Result, causeMessage string) (core.Result, error) {
			resultf := func(pr pam.Result, pect pam.ErrorCauseType, message string, args ...any) (core.Result, error) {
				if causeMessage != "" {
					message = message + ": %s"
					args = append(args, causeMessage)
				}
				return r, pr.Errorf(pect, message, args...)
			}
			switch r {
			case core.ResultConfigurationErr:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeConfiguration, "configuration error")
			case core.ResultRequestingNameForbidden:
				return resultf(pam.ResultUserUnknown, pam.ErrorCauseTypeUser, "remote user %q is forbidden by configuration", requestedUsername)
			case core.ResultOidcAuthorizeTimeout:
				return resultf(pam.ResultIgnore, pam.ErrorCauseTypeUser, "the authorization request was not completed within timeout for user %q", requestedUsername)
			case core.ResultOidcAuthorizeFailed:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, "was not able authorize client for user %q", requestedUsername)
			case core.ResultRequirementResolutionFailed:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, "was not able to resolve user requirement for remote user %q", requestedUsername)
			case core.ResultLoginAllowedResolutionFailed:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, "was not able to resolve if remote user %q is allowed to login", requestedUsername)
			case core.ResultLoginForbidden:
				return resultf(pam.ResultCredentialsInsufficient, pam.ErrorCauseTypeUser, "remote user %q is not allowed to login", requestedUsername)
			case core.ResultUserEnsuringFailed:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, "was not able to ensure remote user %q", requestedUsername)
			case core.ResultNoSuchUser:
				return resultf(pam.ResultUserUnknown, pam.ErrorCauseTypeUser, "remote user %q is unknown", requestedUsername)
			default:
				return resultf(pam.ResultSystemErr, pam.ErrorCauseTypeSystem, "unknown error for remote user %q", requestedUsername)
			}
		},
	}
}

type fdt struct {
	fd int
}

func (this *fdt) Write(p []byte) (int, error) {
	return syscall.Write(this.fd, p)
}

func (this *fdt) Read(p []byte) (int, error) {
	return syscall.Read(this.fd, p)
}

func (this *fdt) Close() error {
	return syscall.Close(this.fd)
}

func openSocket(path string) (*fdt, error) {
	fail := func(err error) (*fdt, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*fdt, error) {
		return fail(fmt.Errorf(message, args...))
	}

	address := syscall.SockaddrUnix{
		Name: path,
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return failf("cannot create socket: %w", err)
	}
	if err := syscall.Connect(fd, &address); err != nil {
		return failf("cannot connect socket: %w", err)
	}

	return &fdt{fd}, nil
}

func pamSmSetcred(ph *pam.Handle, flags pam.Flags, args ...string) pam.Result {
	ph.UncheckedInfof("pamSmSetcred")
	ph.Syslogf(syslog.LOG_DEBUG, "pamSmSetcred: %+v - %+v", flags, args)
	return pam.ResultUserUnknown
}

func resolveEnv(ph *pam.Handle, _ pam.Flags, args ...string) (string, core.ConfigurationKey, string, error) {
	socketPath := core.DefaultSocketPath
	confKey := core.DefaultConfigurationKey
	plainConfKey := string(confKey)

	nArgs := len(args)
	if nArgs >= 1 {
		socketPath = args[0]
	}
	if nArgs >= 2 {
		plainConfKey = args[1]
	}
	if nArgs >= 3 {
		return "", "", "", pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeConfiguration, "too many args provided - syntax: [socketPath] [configurationKey]")
	}
	if err := confKey.Set(plainConfKey); err != nil {
		return "", "", "", pam.ResultSystemErr.Errorf(pam.ErrorCauseTypeConfiguration, "%v", err)
	}

	un, err := ph.GetUser("")
	if err != nil {
		return "", "", "", err
	}
	if len(un) == 0 {
		return "", "", "", pam.ResultUserUnknown.Errorf(pam.ErrorCauseTypeUser, "empty user")
	}

	return socketPath, confKey, un, nil
}
