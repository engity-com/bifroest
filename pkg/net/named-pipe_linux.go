//go:build linux

package net

import (
	"context"
	gonet "net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/engity-com/bifroest/pkg/sys"
)

func newNamedPipe(purpose Purpose, id string) (NamedPipe, error) {
	dir, err := os.MkdirTemp("", "bifroest-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, purpose.String()+"-"+id+".sock")
	ln, err := gonet.Listen("unix", path)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		_ = os.Remove(dir)
		return nil, err
	}
	return &namedPipe{Listener: ln, path: path, deleteOnClose: true, dirToDelete: dir}, nil
}

func setNamedPipeOwner(pipe *namedPipe, user, group string) error {
	credentials := syscall.Credential{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}
	if err := sys.EnrichCredentials(&credentials, user, group); err != nil {
		return err
	}
	if err := os.Chown(pipe.path, int(credentials.Uid), int(credentials.Gid)); err != nil {
		return err
	}
	if pipe.dirToDelete != "" {
		return os.Chown(pipe.dirToDelete, int(credentials.Uid), int(credentials.Gid))
	}
	return nil
}

func connectToNamedPipe(ctx context.Context, path string) (gonet.Conn, error) {
	var dialer gonet.Dialer
	return dialer.DialContext(ctx, "unix", path)
}
