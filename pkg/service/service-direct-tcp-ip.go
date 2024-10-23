package service

import (
	"syscall"
	"time"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func (this localForwardChannelData) dest() (net.HostPort, error) {
	var buf net.HostPort
	if err := buf.Host.Set(this.DestAddr); err != nil {
		return net.HostPort{}, err
	}
	buf.Port = uint16(this.DestPort)
	return buf, nil
}

func (this *service) handleNewDirectTcpIp(_ *glssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx glssh.Context) {
	conn := this.connection(ctx)
	l := conn.logger

	auth, _, _, err := this.resolveAuthorizationAndSession(ctx)
	if err != nil {
		l.WithError(err).
			Error("cannot resolve active authorization and its session; rejecting...")
		_ = newChan.Reject(gossh.ConnectionFailed, "cannot resolve authorization and its session")
		return
	}

	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}
	dest, err := d.dest()
	if err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	l = l.With("dest", dest)

	req := environmentRequest{
		environmentContext{
			service:       this,
			connection:    conn,
			authorization: auth,
		},
		nil,
	}

	env, err := this.environments.Ensure(&req)
	if err != nil {
		l.WithError(err).
			Error("cannot ensure environment; rejecting...")
		_ = newChan.Reject(gossh.Prohibited, "cannot ensure environment")
		return
	}
	defer common.IgnoreCloseError(env)

	if ok, err := env.IsPortForwardingAllowed(dest); err != nil {
		l.WithError(err).
			Error("cannot check if port forwarding is allowed; rejecting...")
		_ = newChan.Reject(gossh.ConnectionFailed, "port forwarding is disabled")
		return
	} else if !ok {
		l.Info("port forwarding requested by client was rejected")
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	dConn, err := env.NewDestinationConnection(ctx, dest)
	if err != nil {
		if this.isAcceptableNewConnectionError(err) {
			l.WithError(err).
				Info("cannot connect to port forwarding destination; rejecting...")
		} else {
			l.WithError(err).
				Warn("cannot connect to port forwarding destination; rejecting...")
		}
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	if dConn == nil {
		l.Info("connection rejected")
		_ = newChan.Reject(gossh.ConnectionFailed, "rejected")
		return
	}
	defer common.IgnoreCloseError(dConn)

	sConn, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer common.IgnoreCloseError(sConn)

	go gossh.DiscardRequests(reqs)

	nameOf := func(isL2r bool) string {
		if isL2r {
			return "source -> destination"
		}
		return "destination -> source"
	}

	_ = sys.FullDuplexCopy(ctx, sConn, dConn, &sys.FullDuplexCopyOpts{
		OnStart: func() {
			l.Debug("port forwarding started")
		},
		OnEnd: func(s2d, d2s int64, duration time.Duration, err error, wasInL2r *bool) {
			ld := l.
				With("s2d", s2d).
				With("d2s", d2s).
				With("duration", duration)
			if wasInL2r != nil {
				ld = ld.With("direction", nameOf(*wasInL2r))
			}

			if err != nil {
				ld.WithError(err).Error("cannot successful handle port forwarding request; canceling...")
			} else {
				ld.Info("port forwarding finished")
			}
		},
		OnStreamEnd: func(isL2r bool, err error) {
			name := "source -> destination"
			if !isL2r {
				name = "destination -> source"
			}
			l.WithError(err).Tracef("coping of %s done", name)
		},
	})
}

func (this *service) onReversePortForwardingRequested(_ glssh.Context, _ string, _ uint32) bool {
	// TODO! Maybe more checks here in the future?
	return true
}

func (this *service) isAcceptableNewConnectionError(err error) bool {
	if err == nil {
		return false
	}

	var sce syscall.Errno
	if errors.As(err, &sce) {
		switch sce {
		case syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.ENETUNREACH:
			return true
		default:
			return false
		}
	}

	return false
}
