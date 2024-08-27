package crypto

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

type RsaRestriction uint8

const (
	RsaRestrictionNone RsaRestriction = iota
	RsaRestrictionAll
	RsaRestrictionAtLeast1024Bits
	RsaRestrictionAtLeast2048Bits
	RsaRestrictionAtLeast3072Bits
	RsaRestrictionAtLeast4096Bits
)

var (
	DefaultRsaRestriction = RsaRestrictionAtLeast4096Bits
)

func (this RsaRestriction) Validate() error {
	switch this {
	case RsaRestrictionNone, RsaRestrictionAll, RsaRestrictionAtLeast1024Bits, RsaRestrictionAtLeast2048Bits, RsaRestrictionAtLeast3072Bits, RsaRestrictionAtLeast4096Bits:
		return nil
	default:
		return fmt.Errorf("illegal rsa key restriction: %d", this)
	}
}

func (this RsaRestriction) MarshalText() (text []byte, err error) {
	switch this {
	case RsaRestrictionNone:
		return []byte("none"), nil
	case RsaRestrictionAll:
		return []byte("all"), nil
	case RsaRestrictionAtLeast1024Bits:
		return []byte("at-least-1024-bits"), nil
	case RsaRestrictionAtLeast2048Bits:
		return []byte("at-least-2048-bits"), nil
	case RsaRestrictionAtLeast3072Bits:
		return []byte("at-least-3072-bits"), nil
	case RsaRestrictionAtLeast4096Bits:
		return []byte("at-least-4096-bits"), nil
	default:
		return nil, fmt.Errorf("illegal rsa key restriction: %d", this)
	}
}

func (this RsaRestriction) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-rsa-key-restriction-%d", this)
}

func (this *RsaRestriction) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "", "none", "forbidden":
		*this = RsaRestrictionNone
	case "all", "unrestricted":
		*this = RsaRestrictionAll
	case "at-least-1024-bits", "atleast1024bits", "at_least_1024_bits", "at-least-1024", "atleast1024", "at_least_1024", "1024", "1024bits":
		*this = RsaRestrictionAtLeast1024Bits
	case "at-least-2048-bits", "atleast2048bits", "at_least_2048_bits", "at-least-2048", "atleast2048", "at_least_2048", "2048", "2048bits":
		*this = RsaRestrictionAtLeast2048Bits
	case "at-least-3072-bits", "atleast3072bits", "at_least_3072_bits", "at-least-3072", "atleast3072", "at_least_3072", "3072", "3072bits":
		*this = RsaRestrictionAtLeast3072Bits
	case "at-least-4096-bits", "atleast4096bits", "at_least_4096_bits", "at-least-4096", "atleast4096", "at_least_4096", "4096", "4096bits":
		*this = RsaRestrictionAtLeast4096Bits
	default:
		return fmt.Errorf("illegal rsa key restriction: %q", string(text))
	}
	return nil
}

func (this *RsaRestriction) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this RsaRestriction) IsZero() bool {
	return this == 0
}

func (this RsaRestriction) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case RsaRestriction:
		return this.isEqualTo(&v)
	case *RsaRestriction:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this RsaRestriction) isEqualTo(other *RsaRestriction) bool {
	return this == *other
}

func (this RsaRestriction) BitsAllowed(in int) bool {
	switch this {
	case RsaRestrictionAll:
		return true
	case RsaRestrictionAtLeast1024Bits:
		return in >= 1024
	case RsaRestrictionAtLeast2048Bits:
		return in >= 2048
	case RsaRestrictionAtLeast3072Bits:
		return in >= 3072
	case RsaRestrictionAtLeast4096Bits:
		return in >= 4096
	default:
		return false
	}
}

func (this RsaRestriction) KeyAllowed(in any) (bool, error) {
	switch v := in.(type) {
	case ssh.Signer:
		return this.KeyAllowed(v.PublicKey())
	case ssh.CryptoPublicKey:
		return this.KeyAllowed(v.CryptoPublicKey())
	case rsa.PublicKey:
		return this.publicKeyAllowed(&v)
	case *rsa.PublicKey:
		return this.publicKeyAllowed(v)
	case rsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	case *rsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	default:
		return false, nil
	}
}

func (this RsaRestriction) publicKeyAllowed(in *rsa.PublicKey) (bool, error) {
	return this.BitsAllowed(in.N.BitLen()), nil
}
