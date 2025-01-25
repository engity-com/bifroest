package protocol

import (
	"context"
	gonet "net"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type MasterSession struct {
	parent *Master
	ref    Ref
}

func (this *MasterSession) Close() error {
	return nil
}

func (this *MasterSession) InitiateTcpForward(ctx context.Context, connectionId connection.Id, target net.HostPort) (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, errors.Network.Newf("cannot initiate direct tcp connection for %v to %v: %w", connectionId, target, err)
	}

	result, err := this.parent.methodTcpForward(ctx, this.ref, connectionId, target)
	if err != nil {
		return fail(err)
	}

	return result, nil
}

func (this *MasterSession) InitiateNamedPipe(ctx context.Context, connectionId connection.Id, purpose net.Purpose) (net.NamedPipe, error) {
	fail := func(err error) (net.NamedPipe, error) {
		return nil, errors.Network.Newf("cannot named pipe for %v of %v: %w", connectionId, purpose, err)
	}

	result, err := this.parent.methodNamedPipe(ctx, this.ref, connectionId, purpose)
	if err != nil {
		return fail(err)
	}

	return result, nil
}

func (this *MasterSession) Ping(ctx context.Context, connectionId connection.Id) error {
	return this.parent.methodPing(ctx, this.ref, connectionId)
}

func (this *MasterSession) GetConnectionExitCode(ctx context.Context, connectionId connection.Id) (int, error) {
	fail := func(err error) (int, error) {
		return 0, errors.Network.Newf("cannot get connection exitCode for %v: %w", connectionId, err)
	}

	result, err := this.parent.methodGetConnectionExitCode(ctx, this.ref, connectionId)
	if errors.Is(err, connection.ErrNotFound) {
		return 0, connection.ErrNotFound
	}
	if err != nil {
		return fail(err)
	}

	return result, nil
}

func (this *MasterSession) GetEnvironment(ctx context.Context, connectionId connection.Id) (sys.EnvVars, error) {
	return this.parent.methodGetEnvironment(ctx, this.ref, connectionId)
}

func (this *MasterSession) Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error {
	return this.parent.methodKill(ctx, this.ref, connectionId, pid, signal)
}
