// Package evidence holds portable evidence data/verification, not journal storage
// or an authority to sign or trust a producer.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/engity-com/bifroest/pkg/errors"
)

// ProducerId identifies the audit producer independently from process and
// chain lifetimes. Its text form is safe to use as a path component.
type ProducerId [sha256.Size]byte

func (this ProducerId) String() string {
	return hex.EncodeToString(this[:])
}

func (this ProducerId) IsZero() bool {
	return this == ProducerId{}
}

func (this ProducerId) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *ProducerId) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return errors.Config.Newf("illegal audit producer ID length: %d", len(text))
	}
	var decoded ProducerId
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.Config.Newf("illegal audit producer ID: %w", err)
	}
	*this = decoded
	return nil
}

func (this *ProducerId) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}
