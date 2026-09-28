package environment

import (
	"context"
	"errors"
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
)

type reverseListenerSession struct {
	imp.ExecutionSession
	called   int
	ctx      context.Context
	id       connection.Id
	host     string
	port     uint16
	listener gonet.Listener
	err      error
}

type reverseListenerEnvironment interface {
	ListenReverseTCP(context.Context, string, uint16) (gonet.Listener, error)
}

func (this *reverseListenerSession) ListenReverseTCP(ctx context.Context, id connection.Id, host string, port uint16) (gonet.Listener, error) {
	this.called++
	this.ctx = ctx
	this.id = id
	this.host = host
	this.port = port
	return this.listener, this.err
}

func TestContainerEnvironmentsListenReverseTCP(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func(imp.ExecutionSession, bool) reverseListenerEnvironment
	}{
		{"docker", func(sess imp.ExecutionSession, allowed bool) reverseListenerEnvironment {
			return &docker{impSession: sess, portForwardingAllowed: allowed}
		}},
		{"kubernetes", func(sess imp.ExecutionSession, allowed bool) reverseListenerEnvironment {
			return &kubernetes{impSession: sess, portForwardingAllowed: allowed}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := &reverseListenerSession{}
			denied := tc.new(sess, false)
			listener, err := denied.ListenReverseTCP(context.Background(), "localhost", 2222)
			require.Nil(t, listener)
			require.True(t, berrors.Permission.IsErr(err))
			require.Zero(t, sess.called)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantListener := &struct{ gonet.Listener }{}
			sess.listener = wantListener
			allowed := tc.new(sess, true)
			listener, err = allowed.ListenReverseTCP(ctx, "127.0.0.1", 8080)
			require.NoError(t, err)
			require.Same(t, wantListener, listener)
			require.Equal(t, 1, sess.called)
			require.Same(t, ctx, sess.ctx)
			require.False(t, sess.id.IsZero())
			require.Equal(t, "127.0.0.1", sess.host)
			require.Equal(t, uint16(8080), sess.port)

			wantErr := errors.New("listen failed")
			sess.listener = nil
			sess.err = wantErr
			listener, err = allowed.ListenReverseTCP(ctx, "localhost", 0)
			require.Nil(t, listener)
			require.ErrorIs(t, err, wantErr)
			require.Equal(t, 2, sess.called)
			require.Equal(t, "localhost", sess.host)
			require.Zero(t, sess.port)
		})
	}
}
