package password

import (
	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/engity-com/bifroest/pkg/errors"
)

func init() {
	instance := &Apr1{}
	Instances[apr1_crypt.MagicPrefix] = instance
}

type Apr1 struct{}

func (p *Apr1) Validate(password string, hash []byte) (bool, error) {
	c := apr1_crypt.New()
	if err := c.Verify(password, hash); errors.Is(err, crypt.ErrKeyMismatch) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}
