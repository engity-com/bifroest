package protocol

import (
	"context"
	"net"
	"strconv"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type MasterSession struct {
	parent *Master
	ref    Ref
}

func (this *MasterSession) Close() error {
	return nil
}

func (this *MasterSession) InitiateDirectTcp(ctx context.Context, connectionId connection.Id, host string, port uint32) (net.Conn, error) {
	fail := func(err error) (net.Conn, error) {
		return nil, errors.Network.Newf("cannot initiate direct tcp connection for %v to %s:%d: %w", connectionId, host, port, err)
	}

	dialer, releaser := this.parent.socks5DialerFor(this.ref)
	defer releaser()

	dest := net.JoinHostPort(host, strconv.FormatInt(int64(port), 10))

	conn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		return fail(err)
	}
	return conn, nil
}

func (this *MasterSession) InitiateAgentForward(ctx context.Context, connectionId connection.Id) (_ net.Conn, socketPath string, _ error) {
	// TODO implement me
	panic("implement me")
}

func (this *MasterSession) Echo(ctx context.Context, connectionId connection.Id, in string) (string, error) {
	return this.parent.methodEcho(ctx, this.ref, connectionId, in)
}

func (this *MasterSession) Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error {
	return this.parent.methodKill(ctx, this.ref, connectionId, pid, signal)
}

func (this *MasterSession) Exit(ctx context.Context, connectionId connection.Id, exitCode int) error {
	return this.parent.methodExit(ctx, this.ref, connectionId, exitCode)
}
