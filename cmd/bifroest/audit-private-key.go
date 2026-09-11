package main

import (
	"fmt"
	"io"
	goos "os"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

const maxAuditPrivateKeySize = 1 << 20

func loadAuditPrivateKey(path string) (bfcrypto.PrivateKey, error) {
	pathInfo, err := goos.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect private key %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("private key %q is not a regular file", path)
	}
	if pathInfo.Size() > maxAuditPrivateKeySize {
		return nil, fmt.Errorf("private key %q exceeds %d bytes", path, maxAuditPrivateKeySize)
	}
	if err := validateAuditPrivateKeyPermissions(path, pathInfo); err != nil {
		return nil, err
	}
	file, err := goos.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open private key %q: %w", path, err)
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect open private key %q: %w", path, err)
	}
	if !goos.SameFile(pathInfo, openInfo) {
		return nil, fmt.Errorf("private key %q changed while opening", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxAuditPrivateKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read private key %q: %w", path, err)
	}
	if len(raw) > maxAuditPrivateKeySize {
		return nil, fmt.Errorf("private key %q exceeds %d bytes", path, maxAuditPrivateKeySize)
	}
	key, err := bfcrypto.ParsePrivateKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %q: %w", path, err)
	}
	return key, nil
}
