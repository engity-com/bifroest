package service

import (
	"context"
	"io"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
)

func (this *service) handleNewSshSession(srv *glssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx glssh.Context) {
	glssh.DefaultSessionHandler(srv, conn, newChan, ctx)
}

func (this *service) handleSshShellSession(sess glssh.Session) {
	this.uncheckedExecuteSshSession(sess, environment.TaskTypeShell)
}

func (this *service) handleSshSftpSession(sess glssh.Session) {
	this.uncheckedExecuteSshSession(sess, environment.TaskTypeSftp)
}

func (this *service) uncheckedExecuteSshSession(sshSess glssh.Session, taskType environment.TaskType) {
	conn := this.connection(sshSess.Context())
	l := conn.logger

	handled := false
	defer func() {
		if !handled {
			l.Fatal("session ended unhandled; maybe there might be previous errors in the logs")
		}
	}()

	l.With("type", taskType).
		With("env", sshSess.Environ()).
		With("command", sshSess.Command()).
		Info("new remote session")

	if exitCode, err := this.executeSession(sshSess, conn, taskType); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			l.Info("session ended unexpectedly; maybe timeout")
			if exitCode < 0 {
				exitCode = 61
			}
			_ = sshSess.Exit(exitCode)
			handled = true
			return
		}
		le := l.WithError(err)
		if errors.IsType(err, errors.User) {
			le.Warn("cannot execute session")
			if exitCode < 0 {
				exitCode = 62
			}
		} else {
			le.Error("cannot execute session")
			if exitCode < 0 {
				exitCode = 63
			}
		}
		_ = sshSess.Exit(exitCode)
		handled = true
	} else {
		l.With("exitCode", exitCode).
			Info("session ended")
		_ = sshSess.Exit(exitCode)
		handled = true
	}
}

func (this *service) executeSession(sshSess glssh.Session, conn *connection, taskType environment.TaskType) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(t errors.Type, msg string, args ...any) (int, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	auth, sess, oldState, err := this.resolveAuthorizationAndSession(sshSess.Context())
	if err != nil {
		return fail(err)
	}

	if err := this.showRememberMe(sshSess, auth, sess, oldState); err != nil {
		return fail(err)
	}

	req := environmentRequest{
		environmentContext{
			service:       this,
			connection:    conn,
			authorization: auth,
		},
		sshSess,
	}

	env, err := this.environments.Ensure(&req)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, env)

	if len(sshSess.RawCommand()) == 0 && taskType == environment.TaskTypeShell {
		banner, err := env.Banner(&req)
		if err != nil {
			return failf(errors.System, "cannot render banner: %w", err)
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(sshSess, banner); err != nil {
				return failf(errors.System, "cannot print banner: %w", err)
			}
		}
	}

	t := environmentTask{
		environmentContext: req.environmentContext,
		sshSession:         sshSess,
		taskType:           taskType,
	}
	if exitCode, err := env.Run(&t); err != nil {
		return failf(errors.System, "run of environment failed: %w", err)
	} else {
		return exitCode, nil
	}
}
