//go:build darwin

package net

import (
	"context"
	"fmt"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/engity-com/bifroest/pkg/sys"
)

const maxDarwinUnixSocketPathBytes = 103

func newNamedPipe(purpose Purpose, id string) (NamedPipe, error) {
	dir, err := os.MkdirTemp("/tmp", "bifroest-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	path, err := darwinNamedPipePath(dir, purpose, id)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	cleanup := func() {
		_ = os.Remove(path)
		_ = os.Remove(dir)
	}

	ln, err := gonet.ListenUnix("unix", &gonet.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		cleanup()
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		cleanup()
		return nil, err
	}
	return &namedPipe{Listener: ln, path: path, deleteOnClose: true, dirToDelete: dir}, nil
}

func darwinNamedPipePath(dir string, purpose Purpose, id string) (string, error) {
	path := filepath.Join(dir, purpose.String()+"-"+id+".sock")
	if strings.ContainsAny(id, "/\x00") || len(path) > maxDarwinUnixSocketPathBytes {
		path = filepath.Join(dir, "s")
	}
	if len(path) > maxDarwinUnixSocketPathBytes {
		return "", fmt.Errorf("unix socket path is too long (%d > %d bytes)", len(path), maxDarwinUnixSocketPathBytes)
	}
	return path, nil
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
	if len(path) > maxDarwinUnixSocketPathBytes {
		return nil, fmt.Errorf("unix socket path is too long (%d > %d bytes)", len(path), maxDarwinUnixSocketPathBytes)
	}
	if strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("unix socket path contains a NUL byte")
	}
	var dialer gonet.Dialer
	return dialer.DialContext(ctx, "unix", path)
}
