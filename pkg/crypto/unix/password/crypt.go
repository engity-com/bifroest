package password

import (
	"bytes"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrNoSuchCrypt = errors.Newf(errors.TypeUnknown, "no such unix password hashing method")
	Instances      = make(map[string]Crypt)
)

type Crypt interface {
	Validate(password, hash []byte) (bool, error)
}

func Validate(password, hash []byte) (bool, error) {
	for prefix, crypt := range Instances {
		if bytes.HasPrefix(hash, []byte(prefix)) {
			return crypt.Validate(password, hash)
		}
	}
	return false, ErrNoSuchCrypt
}
