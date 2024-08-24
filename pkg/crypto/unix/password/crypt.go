package password

import (
	"bytes"
	"sort"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrNoSuchCrypt = errors.Newf(errors.Unknown, "no such unix password hashing method")
	Instances      = make(map[string]Crypt)
)

type Crypt interface {
	Validate(password string, hash []byte) (bool, error)
	Name() string
}

func Validate(password string, hash []byte) (bool, error) {
	for prefix, crypt := range Instances {
		if bytes.HasPrefix(hash, []byte(prefix)) {
			return crypt.Validate(password, hash)
		}
	}
	return false, ErrNoSuchCrypt
}

func GetSupportedCrypts() []string {
	result := make([]string, len(Instances))
	var i int
	for _, v := range Instances {
		result[i] = v.Name()
		i++
	}
	sort.Strings(result)
	return result
}
