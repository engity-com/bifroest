package password

import (
	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/engity-com/bifroest/pkg/errors"
)

func init() {
	instance := &Md5{}
	Instances[md5_crypt.MagicPrefix] = instance
}

type Md5 struct{}

func (p *Md5) Validate(password string, hash []byte) (bool, error) {
	c := md5_crypt.New()
	if err := c.Verify(password, hash); errors.Is(err, crypt.ErrKeyMismatch) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}
