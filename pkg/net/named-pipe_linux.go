//go:build linux

package net

import (
	"context"
	gonet "net"
	"os"
	"path/filepath"
)

func newNamedPipe(purpose Purpose, id string) (NamedPipe, error) {
	dir := os.TempDir()
	_ = os.MkdirAll(dir, 0777)
	path := filepath.Join(os.TempDir(), purpose.String()+"-"+id+".sock")
	ln, err := gonet.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The IMP can run as root while the process using the forwarded socket runs
	// as an arbitrary environment user. The random socket name remains the
	// access token, while the mode allows that user to connect.
	if err := os.Chmod(path, 0666); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &namedPipe{ln, path, true}, nil
}

func connectToNamedPipe(ctx context.Context, path string) (gonet.Conn, error) {
	var dialer gonet.Dialer
	return dialer.DialContext(ctx, "unix", path)
}
