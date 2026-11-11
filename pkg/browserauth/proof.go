// Package browserauth implements the portable possession-proof core for browser
// RememberMe. It does not store keys, authenticate users, or depend on SSH/OS I/O.
package browserauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidProof = errors.New("invalid browser possession proof")

const ChallengeLifetime = time.Minute

// PublicKey is canonical standard Base64 of a 65-byte uncompressed P-256 point,
// as exported by WebCrypto's public exportKey("raw"). No private key is accepted.
type PublicKey string

func (this PublicKey) Parse() (*ecdsa.PublicKey, error) {
	if len(this) != 88 {
		return nil, ErrInvalidProof
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(this))
	if err != nil || len(raw) != 65 || base64.StdEncoding.EncodeToString(raw) != string(this) {
		return nil, ErrInvalidProof
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil || y == nil {
		return nil, ErrInvalidProof
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// Context must be constructed from verified server-side state, never by trusting
// a client's session/identity/target. Revision pins one atomic binding use.
type Context struct {
	Purpose   string `json:"purpose"`
	Origin    string `json:"origin"`
	Slug      string `json:"slug"`
	Flow      string `json:"flow"`
	SessionID string `json:"sessionId"`
	BindingID string `json:"bindingId"`
	Revision  uint64 `json:"revision"`
	Target    string `json:"target"`
}

// Challenge belongs to one bounded server attempt. It is deliberately not
// serializable: reload/restart cannot reconstruct a consumed/expired attempt.
type Challenge struct {
	key     *ecdsa.PublicKey
	payload []byte
	expires time.Time
	used    atomic.Bool
}

func NewChallenge(key PublicKey, scope Context) (*Challenge, error) {
	return newChallenge(key, scope, time.Now())
}

func newChallenge(key PublicKey, scope Context, now time.Time) (*Challenge, error) {
	parsed, err := key.Parse()
	if err != nil {
		return nil, err
	}
	if scope.Purpose != "enroll" && scope.Purpose != "resume" && scope.Purpose != "revoke" {
		return nil, ErrInvalidProof
	}
	if scope.Origin == "" || scope.Flow == "" || scope.SessionID == "" || scope.Target == "" {
		return nil, ErrInvalidProof
	}
	for _, value := range []string{scope.Origin, scope.Slug, scope.Flow, scope.SessionID, scope.BindingID, scope.Target} {
		if len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, ErrInvalidProof
		}
	}
	if scope.Purpose == "enroll" {
		if scope.BindingID != "" || scope.Revision != 0 {
			return nil, ErrInvalidProof
		}
	} else if scope.BindingID == "" || scope.Revision == 0 {
		return nil, ErrInvalidProof
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	expires := now.Add(ChallengeLifetime) // Preserve the monotonic deadline in memory.
	body, err := json.Marshal(struct {
		Context
		Key     PublicKey `json:"publicKey"`
		Nonce   string    `json:"nonce"`
		Expires time.Time `json:"expiresAt"`
	}{scope, key, base64.StdEncoding.EncodeToString(nonce[:]), expires.UTC()})
	if err != nil || len(body) > 16<<10 {
		return nil, ErrInvalidProof
	}
	return &Challenge{key: parsed, payload: append([]byte("bifroest-browser-remember-v1\x00"), body...), expires: expires}, nil
}

func (this *Challenge) Bytes() []byte        { return append([]byte(nil), this.payload...) }
func (this *Challenge) ExpiresAt() time.Time { return this.expires }

// Verify consumes the attempt even on failure. WebCrypto ECDSA/SHA-256 produces
// the fixed 64-byte IEEE-P1363 r||s encoding, not ASN.1 or an SSH signature.
func (this *Challenge) Verify(signature []byte) error { return this.verify(signature, time.Now()) }
func (this *Challenge) verify(signature []byte, now time.Time) error {
	if this == nil || !this.used.CompareAndSwap(false, true) || !now.Before(this.expires) || len(signature) != 64 {
		return ErrInvalidProof
	}
	digest := sha256.Sum256(this.payload)
	if !ecdsa.Verify(this.key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return ErrInvalidProof
	}
	return nil
}
