package crypto

import (
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
)

type AuthorizedKeysFile string

func (this AuthorizedKeysFile) ForEach(consumer func(i int, key ssh.PublicKey, comment string, opts []AuthorizedKeyOption) (canContinue bool, err error)) error {
	if len(this) == 0 {
		return nil
	}

	f, err := os.Open(string(this))
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	return parseAuthorizedKeys(f, consumer)
}

func (this AuthorizedKeysFile) Get() ([]AuthorizedKeyWithOptions, error) {
	return getAuthorizedKeysOf(this)
}

func (this AuthorizedKeysFile) Validate() error {
	return validateAuthorizedKeysOf(this)
}

func (this AuthorizedKeysFile) IsZero() bool {
	return len(this) == 0
}

func (this AuthorizedKeysFile) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizedKeysFile:
		return this.isEqualTo(&v)
	case *AuthorizedKeysFile:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizedKeysFile) isEqualTo(other *AuthorizedKeysFile) bool {
	return this == *other
}
