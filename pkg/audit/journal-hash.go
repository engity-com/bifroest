package audit

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/engity-com/bifroest/pkg/errors"
)

type journalHash [sha256.Size]byte

func hashJournalBytes(domain string, content []byte) journalHash {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(content)
	var result journalHash
	copy(result[:], hash.Sum(nil))
	return result
}

func (this journalHash) String() string {
	return hex.EncodeToString(this[:])
}

func (this journalHash) IsZero() bool {
	return this == journalHash{}
}

func (this journalHash) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *journalHash) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(len(this)) {
		return errors.System.Newf("illegal audit journal hash length: %d", len(text))
	}
	var decoded journalHash
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return errors.System.Newf("illegal audit journal hash: %w", err)
	}
	*this = decoded
	return nil
}
