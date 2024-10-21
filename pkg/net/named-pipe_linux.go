//go:build linux

package net

import (
	"net"
	"os"
	"path/filepath"
)

func newNamedPipe(purpose Purpose, id string) (NamedPipe, error) {
	dir := os.TempDir()
	_ = os.MkdirAll(dir, 0777)
	path := filepath.Join(os.TempDir(), purpose.String()+"-"+id+".sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return &namedPipe{ln, path}, nil
}
