//go:build windows

package net

import (
	"context"
	"fmt"
	gonet "net"

	"github.com/Microsoft/go-winio"
)

const (
	namedPipePrefix = `\\.\pipe\bifroest-`
)

func newNamedPipe(purpose Purpose, id string) (NamedPipe, error) {
	path := fmt.Sprintf("%s%v-%s", namedPipePrefix, purpose, id)

	c := winio.PipeConfig{
		SecurityDescriptor: "",
		MessageMode:        true,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}

	ln, err := winio.ListenPipe(path, &c)
	if err != nil {
		return nil, err
	}
	return &namedPipe{Listener: ln, path: path, deleteOnClose: true}, nil
}

func connectToNamedPipe(ctx context.Context, path string) (gonet.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

func setNamedPipeOwner(_ *namedPipe, user, group string) error {
	if user == "" && group == "" {
		return nil
	}
	return fmt.Errorf("setting named pipe owner to %q:%q is not supported on Windows", user, group)
}
