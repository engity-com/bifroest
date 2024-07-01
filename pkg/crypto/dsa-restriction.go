package crypto

import (
	"crypto/dsa"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

type DsaRestriction uint8

const (
	DsaRestrictionNone DsaRestriction = iota
	DsaRestrictionAll
	DsaRestrictionAtLeast1024Bits
	DsaRestrictionAtLeast2048Bits
	DsaRestrictionAtLeast3072Bits
)

var (
	DefaultDsaRestriction = DsaRestrictionNone
)

func (this DsaRestriction) Validate() error {
	switch this {
	case DsaRestrictionNone, DsaRestrictionAll, DsaRestrictionAtLeast1024Bits, DsaRestrictionAtLeast2048Bits, DsaRestrictionAtLeast3072Bits:
		return nil
	default:
		return fmt.Errorf("illegal dsa key restriction: %d", this)
	}
}

func (this DsaRestriction) MarshalText() (text []byte, err error) {
	switch this {
	case DsaRestrictionNone:
		return []byte("none"), nil
	case DsaRestrictionAll:
		return []byte("all"), nil
	case DsaRestrictionAtLeast1024Bits:
		return []byte("at-least-1024-bits"), nil
	case DsaRestrictionAtLeast2048Bits:
		return []byte("at-least-2048-bits"), nil
	case DsaRestrictionAtLeast3072Bits:
		return []byte("at-least-3072-bits"), nil
	default:
		return nil, fmt.Errorf("illegal dsa key restriction: %d", this)
	}
}

func (this DsaRestriction) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-dsa-key-restriction-%d", this)
}

func (this *DsaRestriction) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "", "none", "forbidden":
		*this = DsaRestrictionNone
	case "all", "unrestricted":
		*this = DsaRestrictionAll
	case "at-least-1024-bits", "atleast1024bits", "at_least_1024_bits", "at-least-1024", "atleast1024", "at_least_1024", "1024", "1024bits":
		*this = DsaRestrictionAtLeast1024Bits
	case "at-least-2048-bits", "atleast2048bits", "at_least_2048_bits", "at-least-2048", "atleast2048", "at_least_2048", "2048", "2048bits":
		*this = DsaRestrictionAtLeast2048Bits
	case "at-least-3072-bits", "atleast3072bits", "at_least_3072_bits", "at-least-3072", "atleast3072", "at_least_3072", "3072", "3072bits":
		*this = DsaRestrictionAtLeast3072Bits
	default:
		return fmt.Errorf("illegal dsa key restriction: %q", string(text))
	}
	return nil
}

func (this *DsaRestriction) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this DsaRestriction) IsZero() bool {
	return this == 0
}

func (this DsaRestriction) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case DsaRestriction:
		return this.isEqualTo(&v)
	case *DsaRestriction:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this DsaRestriction) isEqualTo(other *DsaRestriction) bool {
	return this == *other
}

func (this DsaRestriction) BitsAllowed(in int) bool {
	switch this {
	case DsaRestrictionAll:
		return true
	case DsaRestrictionAtLeast1024Bits:
		return in >= 1024
	case DsaRestrictionAtLeast2048Bits:
		return in >= 2048
	case DsaRestrictionAtLeast3072Bits:
		return in >= 3072
	default:
		return false
	}
}

func (this DsaRestriction) KeyAllowed(in any) (bool, error) {
	switch v := in.(type) {
	case ssh.Signer:
		return this.KeyAllowed(v.PublicKey())
	case ssh.CryptoPublicKey:
		return this.KeyAllowed(v.CryptoPublicKey())
	case dsa.PublicKey:
		return this.publicKeyAllowed(&v)
	case *dsa.PublicKey:
		return this.publicKeyAllowed(v)
	case dsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	case *dsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	default:
		return false, nil
	}
}

func (this DsaRestriction) publicKeyAllowed(in *dsa.PublicKey) (bool, error) {
	return this.BitsAllowed(in.P.BitLen()), nil
}
