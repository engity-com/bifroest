package protocol

import (
	"context"
	"io"
	"net"
	"sync"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/google/uuid"
	"github.com/xtaci/smux"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Client struct {
	Logger log.Logger
}

func (this *Client) Open(ctx context.Context, token []byte, sessionId uuid.UUID, conn net.Conn) (*ClientSession, error) {
	fail := func(err error) (*ClientSession, error) {
		return nil, err
	}

	if err := handleHandshakeFromClientSide(token, this.getLogLevel(), sessionId, conn); err != nil {
		return fail(err)
	}

	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return fail(err)
	}

	result := ClientSession{
		parent:    this,
		session:   sess,
		sessionId: sessionId,
	}

	rms, err := sess.OpenStream()
	if err != nil {
		return fail(err)
	}
	go result.handleLoggingAndErrors(ctx, rms)

	return &result, nil
}

func (this *Client) isClosedError(err error) bool {
	return err != nil && (errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF))
}

func (this *Client) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("imp-protocol-client")
}

func (this *Client) getLogLevel() level.Level {
	if la, ok := this.logger().(level.Aware); ok {
		return la.GetLevel()
	}
	return level.Info
}

type ClientSession struct {
	parent    *Client
	session   *smux.Session
	sessionId uuid.UUID

	errors sync.Map
}

func (this *ClientSession) Echo(connectionId uuid.UUID, in string) (out string, err error) {
	fail := func(err error) (string, error) {
		return "", errors.Network.Newf("echo failed: %w", err)
	}
	out, err = this.methodEcho(connectionId, in)
	if err != nil {
		return fail(err)
	}
	return out, nil
}

func (this *ClientSession) InitiateDirectTcp(connectionId uuid.UUID, host string, port uint32) (net.Conn, error) {
	fail := func(err error) (net.Conn, error) {
		return nil, errors.Network.Newf("initiate direct tcp to %s:%d failed: %w", host, port, err)
	}
	result, err := this.initiateMethodDirectTcp(connectionId, host, port)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

func (this *ClientSession) InitiateAgentForward(connectionId uuid.UUID) (_ net.Conn, socketPath string, _ error) {
	fail := func(err error) (net.Conn, string, error) {
		return nil, "", errors.Network.Newf("initiate agent forward failed: %w", err)
	}
	result, socketPath, err := this.initiateMethodAgentForward(connectionId)
	if err != nil {
		return fail(err)
	}
	return result, socketPath, nil
}

func (this *ClientSession) Kill(connectionId uuid.UUID, pid int, signal sys.Signal) error {
	fail := func(err error) error {
		return errors.Network.Newf("kill of #%d with signal %v failed: %w", pid, signal, err)
	}
	if err := this.methodKill(connectionId, pid, signal); err != nil {
		return fail(err)
	}
	return nil
}

func (this *ClientSession) Exit(connectionId uuid.UUID, exitCode int) error {
	fail := func(err error) error {
		return errors.Network.Newf("exit with cide %d failed: %w", exitCode, err)
	}
	if err := this.methodExit(connectionId, exitCode); err != nil {
		return fail(err)
	}
	return nil
}

func (this *ClientSession) Close() error {
	return this.session.Close()
}

func (this *ClientSession) logger() log.Logger {
	return this.parent.logger().With("sessionId", this.sessionId)
}
