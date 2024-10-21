package net

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/mr-tron/base58"

	"github.com/engity-com/bifroest/pkg/errors"
)

type NamedPipe interface {
	net.Listener
	AcceptNamedPipeConnection() (CloseWriterConn, error)
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

func AsNamedPipe(ln net.Listener, path string) (NamedPipe, error) {
	return &namedPipe{ln, path}, nil
}

type namedPipe struct {
	net.Listener
	path string
}

func (this *namedPipe) AcceptNamedPipeConnection() (CloseWriterConn, error) {
	conn, err := this.Accept()
	if err != nil {
		return nil, err
	}
	return AsCloseWriterConn(conn), nil
}

func (this *namedPipe) Path() string {
	return this.path
}
