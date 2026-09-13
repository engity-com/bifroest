package crypto

import (
	"fmt"
	"io"
	"os"
)

// LoadSecurePrivateKeyFile loads an existing private key without creating or
// replacing it. The path must identify one stable, privately owned regular
// file throughout the read.
func LoadSecurePrivateKeyFile(path string, maximumSize int64) (PrivateKey, error) {
	if maximumSize <= 0 {
		return nil, fmt.Errorf("illegal maximum private key size %d", maximumSize)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect private key %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("private key %q is not a regular file", path)
	}
	if pathInfo.Size() < 0 || pathInfo.Size() > maximumSize {
		return nil, fmt.Errorf("private key %q exceeds %d bytes", path, maximumSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open private key %q: %w", path, err)
	}
	openInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot inspect open private key %q: %w", path, err)
	}
	if !openInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("private key %q changed while opening", path)
	}
	if err := validateSecurePrivateKeyFile(path, file, openInfo); err != nil {
		_ = file.Close()
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot read private key %q: %w", path, err)
	}
	if int64(len(raw)) > maximumSize {
		_ = file.Close()
		return nil, fmt.Errorf("private key %q exceeds %d bytes", path, maximumSize)
	}
	afterInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot inspect private key %q after reading: %w", path, err)
	}
	pathAfter, pathErr := os.Lstat(path)
	if pathErr != nil || !pathAfter.Mode().IsRegular() || !os.SameFile(openInfo, afterInfo) ||
		!os.SameFile(afterInfo, pathAfter) || openInfo.Size() != afterInfo.Size() ||
		openInfo.Mode() != afterInfo.Mode() || !openInfo.ModTime().Equal(afterInfo.ModTime()) {
		_ = file.Close()
		return nil, fmt.Errorf("private key %q changed while reading", path)
	}
	if err := validateSecurePrivateKeyFile(path, file, afterInfo); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("cannot close private key %q: %w", path, err)
	}
	key, err := ParsePrivateKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %q: %w", path, err)
	}
	return key, nil
}
