package crypto

import (
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"golang.org/x/crypto/ssh"
)

type AgeSshRecipient = keydata.AgeSshRecipient
type AgeSshIdentities = keydata.AgeSshIdentities

func NewAgeSshRecipient(key ssh.PublicKey) (*AgeSshRecipient, error) {
	return keydata.NewAgeSshRecipient(key)
}
func NewAgeSshIdentities(keys []PrivateKey) (*AgeSshIdentities, error) {
	return keydata.NewAgeSshIdentities(keys)
}
