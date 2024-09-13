package imp

import (
	"context"
	"io"
	"net"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/imp/protocol"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Imp struct {
	client protocol.Client
}

func (this *Imp) Connect(ctx context.Context, token []byte, sess session.Session, conn net.Conn) (*Session, error) {
	cs, err := this.client.Open(ctx, token, sess.Id(), conn)
	if err != nil {
		return nil, err
	}
	return &Session{
		this,
		cs,
	}, nil
}

func (this *Imp) GetInitSignal(_ session.Session) (sys.Signal, error) {
	return sys.SIGINT, nil
}

type Session struct {
	parent        *Imp
	clientSession *protocol.ClientSession
}

func (this *Session) Echo(connectionId uuid.UUID, in string) (out string, _ error) {
	return this.clientSession.Echo(connectionId, in)
}

func (this *Session) InitiateDirectTcp(connectionId uuid.UUID, host string, port uint32) (net.Conn, error) {
	return this.clientSession.InitiateDirectTcp(connectionId, host, port)
}

func (this *Session) InitiateAgentForward(connectionId uuid.UUID) (_ io.ReadWriteCloser, socketPath string, _ error) {
	return this.clientSession.InitiateAgentForward(connectionId)
}

func (this *Session) Kill(connectionId uuid.UUID, pid int, signal sys.Signal) error {
	return this.clientSession.Kill(connectionId, pid, signal)
}

func (this *Session) Exit(connectionId uuid.UUID, exitCode int) error {
	return this.clientSession.Exit(connectionId, exitCode)
}

func (this *Session) Close() error {
	return this.clientSession.Close()
}
