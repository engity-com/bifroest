package password

import (
	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/engity-com/bifroest/pkg/errors"
)

func init() {
	instance := &Sha256{}
	Instances[sha256_crypt.MagicPrefix] = instance
}

type Sha256 struct{}

func (p *Sha256) Validate(password, hash []byte) (bool, error) {
	c := sha256_crypt.New()
	if err := c.Verify(string(password), hash); errors.Is(err, crypt.ErrKeyMismatch) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}
