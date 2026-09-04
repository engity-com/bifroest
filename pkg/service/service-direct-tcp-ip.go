package service

import (
	"fmt"
	"io"
	"math"
	"syscall"
	"time"

	glssh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
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
	if this.DestPort > math.MaxUint16 {
		return net.HostPort{}, fmt.Errorf("port out of range: %d", this.DestPort)
	}
	buf.Port = uint16(this.DestPort)
	return buf, nil
}

func (this *service) handleNewDirectTcpIp(_ *glssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx glssh.Context) error {
	conn := this.connection(ctx)
	if conn == nil {
		return nil
	}
	l := conn.logger

	auth, _, _, err := this.resolveAuthorizationAndSession(ctx)
	if err != nil {
		l.WithError(err).
			Error("cannot resolve active authorization and its session; rejecting...")
		if rejectErr := newChan.Reject(gossh.ConnectionFailed, "cannot resolve authorization and its session"); rejectErr != nil {
			return rejectErr
		}
		return err
	}

	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		return newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
	}
	dest, err := d.dest()
	if err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		return newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
	}
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil && !policy.AllowsOpen(dest) {
		l.Info("port forwarding requested by client was rejected by authorized key policy")
		return newChan.Reject(gossh.Prohibited, "port forwarding is disabled by authorized key policy")
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
		if rejectErr := newChan.Reject(gossh.Prohibited, "cannot ensure environment"); rejectErr != nil {
			return rejectErr
		}
		return err
	}
	defer common.IgnoreCloseError(env)

	if ok, err := env.IsPortForwardingAllowed(dest); err != nil {
		l.WithError(err).
			Error("cannot check if port forwarding is allowed; rejecting...")
		if rejectErr := newChan.Reject(gossh.ConnectionFailed, "port forwarding is disabled"); rejectErr != nil {
			return rejectErr
		}
		return err
	} else if !ok {
		l.Info("port forwarding requested by client was rejected")
		return newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
	}

	dConn, err := env.NewDestinationConnection(ctx, dest)
	if err != nil {
		var re errors.RemoteError
		if errors.As(err, &re) {
			l.WithError(err).
				Info("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: %v", dest, re))
		} else if ufe := this.reWrapUserFacingErrors(err); ufe != nil {
			l.WithError(ufe).
				Info("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: %v", dest, ufe))
		} else {
			l.WithError(err).
				Warn("cannot connect to port forwarding destination; rejecting...")
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("cannot connect to %v: internal error", dest))
		}
		return nil
	}
	if dConn == nil {
		l.Info("connection rejected")
		_ = newChan.Reject(gossh.ConnectionFailed, "rejected")
		return nil
	}
	defer common.IgnoreCloseError(dConn)

	sConn, reqs, err := newChan.Accept()
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(sConn)

	go gossh.DiscardRequests(reqs)

	nameOf := func(isL2r bool) string {
		if isL2r {
			return "source -> destination"
		}
		return "destination -> source"
	}

	return glssh.FullDuplexCopy(ctx, sConn, dConn, &glssh.FullDuplexCopyOpts{
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
			l.WithError(err).Tracef("copying of %s done", nameOf(isL2r))
		},
	})
}

func (this *service) onReversePortForwardingRequested(ctx glssh.Context, _ gossh.ConnMetadata, host string, port uint32) (bool, error) {
	auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok || auth == nil {
		return false, errors.Newf(errors.System, "no authorization resolved for reverse port forwarding request")
	}
	policy := authorization.AuthorizedKeyPolicyOf(auth)
	if policy != nil && !policy.AllowsListen(host, port) {
		return false, nil
	}
	if port > math.MaxUint16 {
		return false, nil
	}
	var bind net.HostPort
	if err := bind.Host.Set(host); err != nil {
		return false, nil
	}
	bind.Port = uint16(port)
	conn := this.connection(ctx)
	if conn == nil {
		return false, errors.Newf(errors.System, "no connection resolved for reverse port forwarding request")
	}
	req := environmentRequest{environmentContext{this, conn, auth}, nil}
	env, err := this.environments.Ensure(&req)
	if err != nil {
		return false, errors.Newf(errors.System, "cannot ensure environment for reverse port forwarding: %w", err)
	}
	defer common.IgnoreCloseError(env)
	allowed, err := env.IsPortForwardingAllowed(bind)
	if err != nil {
		return false, errors.Newf(errors.System, "cannot check if reverse port forwarding is allowed: %w", err)
	}
	return allowed, nil
}

func (this *service) reWrapUserFacingErrors(err error) *errors.Error {
	if err == nil {
		return nil
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &errors.Error{
			Message:    io.EOF.Error(),
			Cause:      err,
			Type:       errors.Network,
			UserFacing: true,
		}
	}

	var sce syscall.Errno
	if errors.As(err, &sce) {
		switch sce {
		case syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.ENETUNREACH:
			return &errors.Error{
				Message:    sce.Error(),
				Cause:      sce,
				Type:       errors.Network,
				UserFacing: true,
			}
		default:
			return nil
		}
	}

	return nil
}
