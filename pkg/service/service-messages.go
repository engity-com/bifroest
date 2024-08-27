package service

import (
	"io"

	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *service) handleBanner(ctx ssh.Context) string {
	l := this.logger(ctx)

	if b, err := this.Configuration.Ssh.Banner.Render(&bannerContext{ctx}); err != nil {
		l.WithError(err).Warn("cannot retrieve banner; showing none")
		return ""
	} else {
		return b
	}
}

func (this *service) showRememberMe(sshSess ssh.Session, auth authorization.Authorization, _ session.Session, state session.State) error {
	ctx := sshSess.Context()

	pub := auth.FindSessionsPublicKey()
	if pub == nil {
		pub, _ = ctx.Value(handshakeKeyCtxKey).(ssh.PublicKey)
	}
	if pub != nil {
		if v := this.Configuration.Ssh.Keys.RememberMeNotification; !v.IsZero() {
			buf, err := v.Render(newRememberMeNotificationContext(ctx, auth, state == session.StateNew, pub))
			if err != nil {
				return errors.Newf(errors.System, "cannot render remember me notification: %w", err)
			}
			if len(buf) > 0 {
				if _, err := io.WriteString(sshSess, buf); err != nil {
					return errors.Newf(errors.System, "cannot send remember me notification: %w", err)
				}
			}
		}
	}

	return nil
}
