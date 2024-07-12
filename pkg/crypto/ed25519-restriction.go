package crypto

import (
	"crypto/ed25519"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

type Ed25519Restriction uint8

const (
	Ed25519RestrictionNone Ed25519Restriction = iota
	Ed25519RestrictionAll
	Ed25519RestrictionAtLeast256Bits

	DefaultEd25519Restriction = Ed25519RestrictionAll
)

func (this Ed25519Restriction) Validate() error {
	switch this {
	case Ed25519RestrictionNone, Ed25519RestrictionAll, Ed25519RestrictionAtLeast256Bits:
		return nil
	default:
		return fmt.Errorf("illegal ed25519 key restriction: %d", this)
	}
}

func (this Ed25519Restriction) MarshalText() (text []byte, err error) {
	switch this {
	case Ed25519RestrictionNone:
		return []byte("none"), nil
	case Ed25519RestrictionAll:
		return []byte("all"), nil
	case Ed25519RestrictionAtLeast256Bits:
		return []byte("at-least-256-bits"), nil
	default:
		return nil, fmt.Errorf("illegal ed25519 key restriction: %d", this)
	}
}

func (this Ed25519Restriction) String() string {
	if v, err := this.MarshalText(); err == nil {
		return string(v)
	}
	return fmt.Sprintf("illegal-ed25519-key-restriction-%d", this)
}

func (this *Ed25519Restriction) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "", "none", "forbidden":
		*this = Ed25519RestrictionNone
	case "all", "unrestricted":
		*this = Ed25519RestrictionAll
	case "at-least-256-bits", "atleast256bits", "at_least_256_bits", "at-least-256", "atleast256", "at_least_256", "256", "256bits":
		*this = Ed25519RestrictionAtLeast256Bits
	default:
		return fmt.Errorf("illegal ed25519 key restriction: %q", string(text))
	}
	return nil
}

func (this *Ed25519Restriction) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Ed25519Restriction) IsZero() bool {
	return this == 0
}

func (this Ed25519Restriction) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ed25519Restriction:
		return this.isEqualTo(&v)
	case *Ed25519Restriction:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Ed25519Restriction) isEqualTo(other *Ed25519Restriction) bool {
	return this == *other
}

func (this Ed25519Restriction) BitsAllowed(in int) bool {
	switch this {
	case Ed25519RestrictionAll:
		return true
	case Ed25519RestrictionAtLeast256Bits:
		return in >= 256
	default:
		return false
	}
}

func (this Ed25519Restriction) KeyAllowed(in any) (bool, error) {
	switch v := in.(type) {
	case ssh.Signer:
		return this.KeyAllowed(v.PublicKey())
	case ssh.CryptoPublicKey:
		return this.KeyAllowed(v.CryptoPublicKey())
	case ed25519.PublicKey:
		return this.publicKeyAllowed(v)
	case *ed25519.PublicKey:
		return this.publicKeyAllowed(*v)
	case ed25519.PrivateKey:
		return this.publicKeyAllowed(v.Public().(ed25519.PublicKey))
	case *ed25519.PrivateKey:
		return this.publicKeyAllowed(v.Public().(ed25519.PublicKey))
	default:
		return false, nil
	}
}

func (this Ed25519Restriction) publicKeyAllowed(in ed25519.PublicKey) (bool, error) {
	return this.BitsAllowed(len(in) * 8), nil
}
