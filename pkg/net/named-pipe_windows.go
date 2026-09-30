//go:build windows

package net

import (
	"context"
	"fmt"
	gonet "net"

	"golang.org/x/sys/windows"

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

func NewNamedPipeForSid(purpose Purpose, sid string) (NamedPipe, error) {
	if err := purpose.Validate(); err != nil {
		return nil, err
	}
	if _, err := windows.StringToSid(sid); err != nil {
		return nil, fmt.Errorf("invalid named pipe account SID: %w", err)
	}
	id, err := NewNamedPipeId()
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s%v-%s", namedPipePrefix, purpose, id)
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")",
		MessageMode:        true,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	})
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
