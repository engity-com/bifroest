package crypto

import "fmt"

type KeyType uint8

const (
	KeyTypeRsa KeyType = iota
	KeyTypeDsa
	KeyTypeEcdsa
	KeyTypeEd25519
)

func (this KeyType) String() string {
	switch this {
	case KeyTypeRsa:
		return "RSA"
	case KeyTypeDsa:
		return "DSA"
	case KeyTypeEcdsa:
		return "ECDSA"
	case KeyTypeEd25519:
		return "Ed25519"
	default:
		return fmt.Sprintf("illegal-key-type-%d", this)
	}
}
