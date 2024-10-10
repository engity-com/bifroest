package password

import (
	"bytes"

	"github.com/openwall/yescrypt-go"
)

func init() {
	instance := &Yescrypt{}
	Instances["$y$"] = instance
}

type Yescrypt struct{}

func (p *Yescrypt) Validate(password string, hash []byte) (bool, error) {
	rehash, err := yescrypt.Hash([]byte(password), hash)
	if err != nil {
		return false, err
	}
	return bytes.Equal(rehash, hash), nil
}

func (p *Yescrypt) Name() string {
	return "yescrypt"
}
