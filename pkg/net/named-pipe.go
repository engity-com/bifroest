package net

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	gonet "net"
	"os"
	"time"

	"github.com/mr-tron/base58"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type NamedPipe interface {
	gonet.Listener
	AcceptConn() (CloseWriterConn, error)
	Path() string
}

func NewNamedPipe(purpose Purpose) (NamedPipe, error) {
	id, err := NewNamedPipeId()
	if err != nil {
		return nil, errors.Network.Newf("cannot create named pipe for %s: %w", purpose, err)
	}
	return NewNamedPipeWithId(purpose, id)
}

func NewNamedPipeWithId(purpose Purpose, id string) (result NamedPipe, err error) {
	fail := func(err error) (NamedPipe, error) {
		return nil, errors.Network.Newf("cannot create named pipe for %s: %w", purpose, err)
	}

	if err := purpose.Validate(); err != nil {
		return fail(err)
	}
	if len(id) == 0 {
		return fail(errors.Network.Newf("empty named pipe id"))
	}

	result, err = newNamedPipe(purpose, id)
	if err != nil {
		return fail(err)
	}

	return result, nil
}

func NewNamedPipeId() (string, error) {
	fail := func(err error) (string, error) {
		return "", err
	}

	buf := make([]byte, 24)
	n, err := rand.Read(buf[:16])
	if err != nil {
		return fail(err)
	}
	if n != 16 {
		return fail(errors.System.Newf("cannot read enough random bytes (%d < %d)", n, 16))
	}
	now := time.Now().UnixMilli()
	binary.LittleEndian.PutUint64(buf[16:], uint64(now))

	return base58.Encode(buf), nil
}

func AsNamedPipe(ln gonet.Listener, path string) (NamedPipe, error) {
	return &namedPipe{ln, path, false}, nil
}

func ConnectToNamedPipe(ctx context.Context, path string) (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, errors.Network.Newf("cannot connect to named pipe for %s: %w", path, err)
	}
	result, err := connectToNamedPipe(ctx, path)
	if err != nil {
		return fail(err)
	}
	return result, err
}

type namedPipe struct {
	gonet.Listener
	path          string
	deleteOnClose bool
}

func (this *namedPipe) AcceptConn() (CloseWriterConn, error) {
	conn, err := this.Accept()
	if err != nil {
		return nil, err
	}
	return AsCloseWriterConn(conn), nil
}

func (this *namedPipe) Path() string {
	return this.path
}

func (this *namedPipe) Close() (rErr error) {
	defer common.KeepError(&rErr, func() error {
		if !this.deleteOnClose {
			return nil
		}
		if err := os.Remove(this.path); err != nil && !sys.IsNotExist(err) {
			return err
		}
		return nil
	})
	return this.Listener.Close()
}
