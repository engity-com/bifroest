package password

import (
	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/engity-com/bifroest/pkg/errors"
)

func init() {
	instance := &Sha512{}
	Instances[sha512_crypt.MagicPrefix] = instance
}

type Sha512 struct{}

func (p *Sha512) Validate(password string, hash []byte) (bool, error) {
	c := sha512_crypt.New()
	if err := c.Verify(password, hash); errors.Is(err, crypt.ErrKeyMismatch) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (p *Sha512) Name() string {
	return "sha512"
}
