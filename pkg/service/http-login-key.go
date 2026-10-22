package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
)

var errWebKeyProof = errors.New("invalid HTTP public-key possession proof")

func parseWebPublicKey(value string) (ssh.PublicKey, error) {
	if len(value) > 12<<10 {
		return nil, errWebKeyProof
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(wire) > 8<<10 || base64.StdEncoding.EncodeToString(wire) != value {
		return nil, errWebKeyProof
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return nil, errWebKeyProof
	}
	base := key
	if cert, ok := key.(*ssh.Certificate); ok {
		base = cert.Key
	}
	switch base.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return nil, errWebKeyProof
	}
	cryptoKey, ok := base.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errWebKeyProof
	}
	switch actual := cryptoKey.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		if len(actual) != ed25519.PublicKeySize {
			return nil, errWebKeyProof
		}
	case *rsa.PublicKey:
		if actual.N.BitLen() < 2048 || actual.N.BitLen() > 8192 {
			return nil, errWebKeyProof
		}
	case *ecdsa.PublicKey:
		if actual.Curve.Params().BitSize < 256 {
			return nil, errWebKeyProof
		}
	default:
		return nil, errWebKeyProof
	}
	return key, nil
}

func webKeyChallenge(conn *webLoginConnection, key ssh.PublicKey, expires time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("cannot create key challenge")
	}
	fields := struct {
		Origin       string    `json:"origin"`
		Slug         string    `json:"slug"`
		User         string    `json:"user"`
		ConnectionId string    `json:"connectionId"`
		PublicKey    string    `json:"publicKeyFingerprint"`
		Nonce        string    `json:"nonce"`
		ExpiresAt    time.Time `json:"expiresAt"`
	}{conn.scope.Origin, conn.scope.Slug, conn.remote.user, conn.Id().String(), ssh.FingerprintSHA256(key), base64.RawURLEncoding.EncodeToString(nonce[:]), expires}
	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("cannot create key challenge")
	}
	return append([]byte("bifroest-http-public-key-v1\x00"), payload...), nil
}

func verifyWebKeyProof(key ssh.PublicKey, challenge []byte, encoded string) error {
	wire, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(wire) > 8<<10 || base64.StdEncoding.EncodeToString(wire) != encoded {
		return errWebKeyProof
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(wire, &signature); err != nil || len(signature.Rest) != 0 {
		return errWebKeyProof
	}
	// RSA/SHA-1 and DSA are not enabled by this new protocol. Verify still checks
	// that the chosen signature format belongs to the exact presented key.
	switch signature.Format {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
	default:
		return errWebKeyProof
	}
	if err := key.Verify(challenge, &signature); err != nil {
		return errWebKeyProof
	}
	return nil
}

func (this *webService) authorizeWebKey(attempt *webLoginAttempt, key ssh.PublicKey) (authorization.Authorization, error) {
	challenge, err := webKeyChallenge(attempt.conn, key, attempt.expires)
	if err != nil {
		return nil, err
	}
	encoded, err := attempt.exchange(webLoginStep{Kind: "public-key", Challenge: base64.StdEncoding.EncodeToString(challenge)})
	if err != nil {
		return nil, err
	}
	if err := verifyWebKeyProof(key, challenge, encoded); err != nil {
		return nil, err
	}
	if err := attempt.conn.Lifetime().Err(); err != nil {
		return nil, err
	}
	return this.service.authorizer.AuthorizePublicKey(&publicKeyAuthorizeRequest{authorizeRequest: authorizeRequest{service: this.service, connection: attempt.conn}, publicKey: key, verified: true})
}
