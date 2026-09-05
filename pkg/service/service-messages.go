package service

import (
	"io"

	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *service) handleBanner(ctx essh.Context, _ gossh.ConnMetadata) (string, error) {
	if b, err := this.Configuration.Ssh.Banner.Render(&connectionContext{ctx}); err != nil {
		return "", errors.Newf(errors.System, "cannot retrieve SSH banner: %w", err)
	} else {
		return b, nil
	}
}

func (this *service) showRememberMe(sshSess essh.Session, auth authorization.Authorization, _ session.Session, state session.State) error {
	ctx := sshSess.Context()

	pub := auth.FindSessionsPublicKey()
	if pub == nil {
		pub, _ = ctx.Value(handshakeKeyCtxKey).(essh.PublicKey)
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
