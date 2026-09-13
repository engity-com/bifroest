package crypto

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
)

type PublicKeysFile string

const maxMaterializedPublicKeysFileSize int64 = 4 * 1024 * 1024

func (this PublicKeysFile) ForEach(consumer func(i int, key ssh.PublicKey, comment string) (canContinue bool, err error)) error {
	return this.forEach(0, consumer)
}

func (this PublicKeysFile) forEach(maximumBytes int64, consumer func(i int, key ssh.PublicKey, comment string) (canContinue bool, err error)) error {
	if this.IsZero() {
		return nil
	}
	path := string(this)
	pathInfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("public keys file %q is not a regular file", path)
	}
	if maximumBytes > 0 && pathInfo.Size() > maximumBytes {
		return fmt.Errorf("public keys file %q exceeds %d bytes", path, maximumBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)
	openInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, openInfo) {
		return fmt.Errorf("public keys file %q changed while opening", path)
	}
	if maximumBytes <= 0 {
		return parsePublicKeys(f, consumer)
	}
	limited := &io.LimitedReader{R: f, N: maximumBytes + 1}
	parseErr := parsePublicKeys(limited, consumer)
	if limited.N == 0 {
		return fmt.Errorf("public keys file %q exceeds %d bytes", path, maximumBytes)
	}
	return parseErr
}

// Get materializes at most 4 MiB of public keys. Use ForEach for larger files.
func (this PublicKeysFile) Get() ([]ssh.PublicKey, error) {
	var result []ssh.PublicKey
	err := this.forEach(maxMaterializedPublicKeysFileSize, func(_ int, key ssh.PublicKey, _ string) (bool, error) {
		result = append(result, key)
		return true, nil
	})
	return result, err
}

func (this PublicKeysFile) Validate() error {
	return validatePublicKeysOf(this)
}

func (this PublicKeysFile) IsZero() bool {
	return strings.TrimSpace(string(this)) == ""
}

func (this *PublicKeysFile) Trim() error {
	*this = PublicKeysFile(strings.TrimSpace(string(*this)))
	return nil
}

func (this PublicKeysFile) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case PublicKeysFile:
		return this == v
	case *PublicKeysFile:
		return v != nil && this == *v
	default:
		return false
	}
}
