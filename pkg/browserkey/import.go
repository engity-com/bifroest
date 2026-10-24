package browserkey

import (
	"bytes"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

var ErrImport = errors.New("browser login key cannot be imported")

const MaxPrivateKeyBytes = 64 << 10
const MaxPassphraseBytes = 4096
const MaxCertificateBytes = 12 << 10
const MaxBcryptRounds = 64

// Import opens one local key, optionally paired with one exact SSH certificate.
// Only public metadata can leave this boundary. Errors never contain key data,
// passphrases, file comments, parser diagnostics or untrusted certificate fields.
func Import(privateKey, passphrase, certificate []byte, scope Scope) (*Key, error) {
	if len(privateKey) == 0 || len(privateKey) > MaxPrivateKeyBytes || len(passphrase) > MaxPassphraseBytes || len(certificate) > MaxCertificateBytes || !scope.valid() {
		return nil, ErrImport
	}
	trimmed := bytes.TrimSpace(privateKey)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil, ErrImport
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrImport
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
	case "OPENSSH PRIVATE KEY":
		if !boundedOpenSSH(block.Bytes) {
			return nil, ErrImport
		}
	default:
		return nil, ErrImport
	}
	signer, err := ssh.ParsePrivateKey(trimmed)
	if _, encrypted := err.(*ssh.PassphraseMissingError); encrypted {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(trimmed, passphrase)
	}
	if err != nil || !supported(signer.PublicKey()) {
		return nil, ErrImport
	}
	key := signer.PublicKey()
	if len(certificate) != 0 {
		// ParseAuthorizedKey ignores invalid lines; require exactly one actual
		// non-comment line first, so malformed/extra entries are not skipped.
		line := bytes.TrimSpace(certificate)
		if bytes.ContainsAny(line, "\r\n") || bytes.HasPrefix(line, []byte("#")) {
			return nil, ErrImport
		}
		pub, _, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrImport
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok || cert.CertType != ssh.UserCert || !bytes.Equal(cert.Key.Marshal(), key.Marshal()) || !supported(cert) || len(cert.Marshal()) > 8<<10 {
			return nil, ErrImport
		}
		key = cert
	}
	return &Key{signer: signer, key: key, scope: scope}, nil
}

// This is only an envelope/resource guard; x/crypto/ssh owns actual parsing,
// decryption and validation. The browser's cancellable worker also needs a hard
// deadline because even valid bounded RSA/KDF work can be slow on small devices.
func boundedOpenSSH(raw []byte) bool {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return false
	}
	var envelope struct {
		Cipher, KDF, Options string
		Keys                 uint32
		Public, Private      []byte
	}
	if ssh.Unmarshal(raw[len(magic):], &envelope) != nil || envelope.Keys != 1 {
		return false
	}
	if envelope.Cipher == "none" {
		return envelope.KDF == "none" && envelope.Options == ""
	}
	if envelope.KDF != "bcrypt" || envelope.Cipher != "aes256-ctr" && envelope.Cipher != "aes256-cbc" {
		return false
	}
	var options struct {
		Salt   []byte
		Rounds uint32
	}
	return ssh.Unmarshal([]byte(envelope.Options), &options) == nil && len(options.Salt) > 0 && len(options.Salt) <= 1024 && options.Rounds > 0 && options.Rounds <= MaxBcryptRounds
}
