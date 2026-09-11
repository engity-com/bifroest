package crypto

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
)

type PublicKeysFile string

func (this PublicKeysFile) ForEach(consumer func(i int, key ssh.PublicKey, comment string) (canContinue bool, err error)) error {
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
	if pathInfo.Size() > MaxBootstrapInputSize {
		return fmt.Errorf("public keys file %q exceeds %d bytes", path, MaxBootstrapInputSize)
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
	return parsePublicKeys(f, consumer)
}

func (this PublicKeysFile) Get() ([]ssh.PublicKey, error) {
	return getPublicKeysOf(this)
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
