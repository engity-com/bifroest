// Package browserkey implements the portable SSH-key browser login proof. It
// performs no network, filesystem, session or account operations. Private keys
// belong only to a short-lived client worker, never to a server HTTP request.
package browserkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

var ErrProof = errors.New("invalid HTTP public-key possession proof")

const ChallengeLifetime = 2 * time.Minute
const domain = "bifroest-http-public-key-v1\x00"

// Scope pins the actual HTTPS origin/port, case-sensitive slug and original,
// possibly empty requesting name. It is not a verified authentication identity.
type Scope struct {
	Origin string `json:"origin"`
	Slug   string `json:"slug"`
	User   string `json:"user"`
}

func (this Scope) valid() bool {
	parsed, err := url.Parse(this.Origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(this.Origin, "#") || parsed.Opaque != "" || len(this.Origin) > 1024 {
		return false
	}
	if len(this.User) > 256 || !utf8.ValidString(this.User) || strings.ContainsFunc(this.User, unicode.IsControl) {
		return false
	}
	if this.Slug == "" {
		return true
	}
	parts := strings.Split(this.Slug, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if len(part) < 1 || len(part) > 64 {
			return false
		}
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

type challenge struct {
	Scope
	ConnectionID string    `json:"connectionId"`
	PublicKey    string    `json:"publicKeyFingerprint"`
	Nonce        string    `json:"nonce"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func decode64(value string, limit int) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(limit) {
		return nil, ErrProof
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) > limit || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, ErrProof
	}
	return raw, nil
}

// ParsePublicKey is shared with the server, including its original key policy.
// Certificates remain intact; current trust, principals, options and validity
// are checked by the server's existing authorizers after possession proof.
func ParsePublicKey(value string) (ssh.PublicKey, error) {
	wire, err := decode64(value, 8<<10)
	if err != nil {
		return nil, ErrProof
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil || !supported(key) {
		return nil, ErrProof
	}
	return key, nil
}

func supported(key ssh.PublicKey) bool {
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	if key == nil {
		return false
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	switch actual := cryptoKey.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return key.Type() == ssh.KeyAlgoED25519 && len(actual) == ed25519.PublicKeySize
	case *rsa.PublicKey:
		return key.Type() == ssh.KeyAlgoRSA && actual.N.BitLen() >= 2048 && actual.N.BitLen() <= 8192
	case *ecdsa.PublicKey:
		return key.Type() == ssh.KeyAlgoECDSA256 || key.Type() == ssh.KeyAlgoECDSA384 || key.Type() == ssh.KeyAlgoECDSA521
	default:
		return false
	}
}

// NewChallenge preserves the v1 wire format. Scope and connection ID must be
// constructed from trusted server state, not client identity assertions.
func NewChallenge(scope Scope, connectionID string, key ssh.PublicKey, expires time.Time) ([]byte, error) {
	if !scope.valid() || !supported(key) || !validID(connectionID) || expires.IsZero() {
		return nil, ErrProof
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrProof
	}
	body, err := json.Marshal(challenge{scope, connectionID, ssh.FingerprintSHA256(key), base64.RawURLEncoding.EncodeToString(nonce[:]), expires})
	if err != nil {
		return nil, ErrProof
	}
	return append([]byte(domain), body...), nil
}

func validID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for index, c := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if c != '-' {
				return false
			}
		} else if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Verify accepts only original SSH wire signatures, not ASN.1 or P1363. The
// server owns attempt consumption/expiry; verification does not authorize users.
func Verify(key ssh.PublicKey, challenge []byte, encoded string) error {
	wire, err := decode64(encoded, 8<<10)
	if err != nil {
		return ErrProof
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(wire, &signature); err != nil || len(signature.Rest) != 0 {
		return ErrProof
	}
	switch signature.Format {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
	default:
		return ErrProof
	}
	if !supported(key) || key.Verify(challenge, &signature) != nil {
		return ErrProof
	}
	return nil
}

// Key is opaque and not serializable. One instance can attempt exactly one
// domain/scope/key/expiry-checked signature, including failed attempts. It is
// deliberately not an ssh.Signer or a general-purpose signing service.
type Key struct {
	mutex  sync.Mutex
	signer ssh.Signer
	key    ssh.PublicKey
	scope  Scope
}

// MarshalJSON intentionally exposes no signer or imported/private material.
func (this *Key) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (this *Key) PublicKey() string {
	if this == nil || this.key == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(this.key.Marshal())
}
func (this *Key) Fingerprint() string {
	if this == nil || this.key == nil {
		return ""
	}
	return ssh.FingerprintSHA256(this.key)
}

// Close releases references; Go/browser garbage collection does not guarantee
// secure physical erasure. A browser worker must additionally be terminated.
func (this *Key) Close() {
	if this == nil {
		return
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.signer = nil
}

func (this *Key) Sign(encoded string, expires time.Time) (string, error) {
	return this.sign(encoded, expires, time.Now())
}

func (this *Key) sign(encoded string, expires, now time.Time) (string, error) {
	if this == nil {
		return "", ErrProof
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	signer := this.signer
	this.signer = nil // Consume even malformed/foreign/expired requests.
	if signer == nil {
		return "", ErrProof
	}
	raw, err := decode64(encoded, 8<<10)
	if err != nil || !bytes.HasPrefix(raw, []byte(domain)) {
		return "", ErrProof
	}
	body := raw[len(domain):]
	var selected challenge
	if json.Unmarshal(body, &selected) != nil {
		return "", ErrProof
	}
	// Canonical roundtrip rejects duplicate/unknown/null fields, invalid Unicode,
	// aliases and trailing input without ever reconstructing the signed bytes.
	canonical, err := json.Marshal(selected)
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(selected.Nonce)
	if err != nil || !bytes.Equal(body, canonical) || selected.Scope != this.scope || !validID(selected.ConnectionID) ||
		selected.PublicKey != this.Fingerprint() || nonceErr != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != selected.Nonce ||
		!selected.ExpiresAt.Equal(expires) || !now.Before(expires) || expires.Sub(now) > ChallengeLifetime {
		return "", ErrProof
	}
	var signature *ssh.Signature
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		algorithm, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return "", ErrProof
		}
		signature, err = algorithm.SignWithAlgorithm(rand.Reader, raw, ssh.KeyAlgoRSASHA512)
	} else {
		signature, err = signer.Sign(rand.Reader, raw)
	}
	if err != nil {
		return "", ErrProof
	}
	proof := base64.StdEncoding.EncodeToString(ssh.Marshal(signature))
	if Verify(this.key, raw, proof) != nil {
		return "", ErrProof
	}
	return proof, nil
}
