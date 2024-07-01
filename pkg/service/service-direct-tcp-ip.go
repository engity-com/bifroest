package service

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func (this *service) handleNewDirectTcpIp(_ *ssh.Server, _ *gssh.ServerConn, newChan gssh.NewChannel, ctx ssh.Context) {
	l := this.logger(ctx)

	d := localForwardChannelData{}
	if err := gssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		l.WithError(err).
			Info("cannot parse client's forward data; rejecting...")
		_ = newChan.Reject(gssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	l = l.With("destAddr", d.DestAddr).
		With("destPort", d.DestPort)

	env, ok := ctx.Value(environmentKeyCtxKey).(environment.Environment)
	if !ok {
		l.Info("cannot do port forwarding without an active environment; rejecting...")
		_ = newChan.Reject(gssh.Prohibited, "no active environment")
		return
	}

	if ok, err := env.IsPortForwardingAllowed(d.DestAddr, d.DestPort); err != nil {
		l.WithError(err).
			Error("cannot check if port forwarding is allowed; rejecting...")
		_ = newChan.Reject(gssh.ConnectionFailed, "port forwarding is disabled")
		return
	} else if !ok {
		l.Info("port forwarding requested by client was rejected")
		_ = newChan.Reject(gssh.Prohibited, "port forwarding is disabled")
		return
	}

	dConn, err := env.NewDestinationConnection(ctx, d.DestAddr, d.DestPort)
	if err != nil {
		if this.isAcceptableNewConnectionError(err) {
			l.WithError(err).
				Info("cannot connect to port forwarding destination; rejecting...")
		} else {
			l.WithError(err).
				Warn("cannot connect to port forwarding destination; rejecting...")
		}
		_ = newChan.Reject(gssh.ConnectionFailed, err.Error())
		return
	}
	defer common.IgnoreCloseError(dConn)

	sConn, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer common.IgnoreCloseError(sConn)

	go gssh.DiscardRequests(reqs)

	type done struct {
		name  string
		error error
	}
	dones := make(chan done, 2)
	var wg sync.WaitGroup
	var rErr error
	var direction string
	var s2d, d2s atomic.Int64
	started := time.Now()
	go func() {
		wg.Wait()
		close(dones)

		ld := l.
			With("s2d", s2d.Load()).
			With("d2s", d2s.Load()).
			With("duration", time.Since(started).Truncate(time.Microsecond))

		if rErr != nil {
			if direction != "" {
				ld = ld.With("direction", direction)
			}
			ld.WithError(rErr).Error("cannot successful handle port forwarding request; cancelling...")
		} else {
			ld.Info("port forwarding finished")
		}
	}()

	copyFull := func(from io.Reader, to io.Writer, name string) {
		defer wg.Done()
		n, err := io.Copy(to, from)
		if this.isRelevantError(err) {
			dones <- done{name, err}
		} else {
			dones <- done{name, nil}
		}
		if name == "destination -> source" {
			d2s.Store(n)
		} else {
			s2d.Store(n)
		}
		l.WithError(err).Tracef("coping of %s done", name)
	}
	wg.Add(2)
	go copyFull(dConn, sConn, "destination -> source")
	go copyFull(sConn, dConn, "source -> destination")

	l.Debug("port forwarding started")

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); this.isSilentError(err) {
				rErr = err
				direction = ""
			}
			return
		case v := <-dones:
			if this.isRelevantError(v.error) {
				rErr = v.error
				direction = v.name
			}
			return
		}
	}
}

func (this *service) onReversePortForwardingRequested(_ ssh.Context, _ string, _ uint32) bool {
	// TODO! Maybe more checks here in the future?
	return true
}
