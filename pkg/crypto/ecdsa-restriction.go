package crypto

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

type EcdsaRestriction uint8

const (
	EcdsaRestrictionNone EcdsaRestriction = iota
	EcdsaRestrictionAll
	EcdsaRestrictionAtLeast256Bits
	EcdsaRestrictionAtLeast384Bits
	EcdsaRestrictionAtLeast521Bits
)

var (
	DefaultEcdsaRestriction = EcdsaRestrictionAtLeast384Bits
)

func (this EcdsaRestriction) Validate() error {
	switch this {
	case EcdsaRestrictionNone, EcdsaRestrictionAll, EcdsaRestrictionAtLeast256Bits, EcdsaRestrictionAtLeast384Bits, EcdsaRestrictionAtLeast521Bits:
		return nil
	default:
		return fmt.Errorf("illegal ecdsa key restriction: %d", this)
	}
}

func (this EcdsaRestriction) MarshalText() (text []byte, err error) {
	switch this {
	case EcdsaRestrictionNone:
		return []byte("none"), nil
	case EcdsaRestrictionAll:
		return []byte("all"), nil
	case EcdsaRestrictionAtLeast256Bits:
		return []byte("at-least-256-bits"), nil
	case EcdsaRestrictionAtLeast384Bits:
		return []byte("at-least-384-bits"), nil
	case EcdsaRestrictionAtLeast521Bits:
		return []byte("at-least-521-bits"), nil
	default:
		return nil, fmt.Errorf("illegal ecdsa key restriction: %d", this)
	}
}

func (this EcdsaRestriction) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ecdsa-key-restriction-%d", this)
}

func (this *EcdsaRestriction) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "", "none", "forbidden":
		*this = EcdsaRestrictionNone
	case "all", "unrestricted":
		*this = EcdsaRestrictionAll
	case "at-least-256-bits", "atleast256bits", "at_least_256_bits", "at-least-256", "atleast256", "at_least_256", "256", "256bits":
		*this = EcdsaRestrictionAtLeast256Bits
	case "at-least-384-bits", "atleast384bits", "at_least_384_bits", "at-least-384", "atleast384", "at_least_384", "384", "384bits":
		*this = EcdsaRestrictionAtLeast384Bits
	case "at-least-521-bits", "atleast521bits", "at_least_521_bits", "at-least-521", "atleast521", "at_least_521", "521", "521bits":
		*this = EcdsaRestrictionAtLeast521Bits
	default:
		return fmt.Errorf("illegal ecdsa key restriction: %q", string(text))
	}
	return nil
}

func (this *EcdsaRestriction) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this EcdsaRestriction) IsZero() bool {
	return this == 0
}

func (this EcdsaRestriction) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EcdsaRestriction:
		return this.isEqualTo(&v)
	case *EcdsaRestriction:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EcdsaRestriction) isEqualTo(other *EcdsaRestriction) bool {
	return this == *other
}

func (this EcdsaRestriction) BitsAllowed(in int) bool {
	switch this {
	case EcdsaRestrictionAll:
		return true
	case EcdsaRestrictionAtLeast256Bits:
		return in >= 256
	case EcdsaRestrictionAtLeast384Bits:
		return in >= 384
	case EcdsaRestrictionAtLeast521Bits:
		return in >= 521
	default:
		return false
	}
}

func (this EcdsaRestriction) KeyAllowed(in any) (bool, error) {
	switch v := in.(type) {
	case PrivateKey:
		return this.KeyAllowed(v.ToSdk())
	case PublicKey:
		return this.KeyAllowed(v.ToSdk())
	case ssh.Signer:
		return this.KeyAllowed(v.PublicKey())
	case ssh.CryptoPublicKey:
		return this.KeyAllowed(v.CryptoPublicKey())
	case ecdsa.PublicKey:
		return this.publicKeyAllowed(&v)
	case *ecdsa.PublicKey:
		return this.publicKeyAllowed(v)
	case ecdsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	case *ecdsa.PrivateKey:
		return this.publicKeyAllowed(&v.PublicKey)
	default:
		return false, nil
	}
}

func (this EcdsaRestriction) publicKeyAllowed(in *ecdsa.PublicKey) (bool, error) {
	return this.BitsAllowed(in.Curve.Params().BitSize), nil
}
