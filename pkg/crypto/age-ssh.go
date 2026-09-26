package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"io"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/errors"
)

type AgeSshRecipient struct {
	recipient   age.Recipient
	fingerprint string
}

func NewAgeSshRecipient(key ssh.PublicKey) (*AgeSshRecipient, error) {
	if key == nil {
		return nil, errors.Config.Newf("nil SSH public key for age recipient")
	}
	var recipient age.Recipient
	var err error
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		recipient, err = agessh.NewEd25519Recipient(key)
	case ssh.KeyAlgoRSA:
		recipient, err = agessh.NewRSARecipient(key)
	default:
		err = errors.Config.Newf("SSH public key type %q cannot be used as an age recipient", key.Type())
	}
	if err != nil {
		return nil, errors.Config.Newf("%w", err)
	}
	return &AgeSshRecipient{recipient: recipient, fingerprint: ssh.FingerprintSHA256(key)}, nil
}

func (this *AgeSshRecipient) Fingerprint() string {
	if this == nil {
		return ""
	}
	return this.fingerprint
}

func (this *AgeSshRecipient) Encrypt(output io.Writer) (io.WriteCloser, error) {
	if this == nil || this.recipient == nil {
		return nil, errors.System.Newf("nil age SSH recipient")
	}
	if output == nil {
		return nil, errors.System.Newf("nil age encryption output")
	}
	writer, err := age.Encrypt(output, this.recipient)
	if err != nil {
		return nil, errors.System.Newf("%w", err)
	}
	return ageSshEncryptWriter{WriteCloser: writer}, nil
}

type AgeSshIdentities struct {
	identities              []age.Identity
	identitiesByFingerprint map[string]age.Identity
}

func NewAgeSshIdentities(keys []PrivateKey) (*AgeSshIdentities, error) {
	if len(keys) == 0 {
		return nil, errors.Config.Newf("no age SSH identities")
	}
	identities := make([]age.Identity, 0, len(keys))
	identitiesByFingerprint := make(map[string]age.Identity, len(keys))
	for _, key := range keys {
		if key == nil {
			return nil, errors.Config.Newf("nil age SSH identity")
		}
		var identity age.Identity
		var err error
		switch value := key.ToSdk().(type) {
		case ed25519.PrivateKey:
			identity, err = agessh.NewEd25519Identity(value)
		case *ed25519.PrivateKey:
			identity, err = agessh.NewEd25519Identity(*value)
		case *rsa.PrivateKey:
			identity, err = agessh.NewRSAIdentity(value)
		default:
			err = errors.Config.Newf("SSH private key type %q cannot be used as an age identity", key.Type())
		}
		if err != nil {
			return nil, errors.Config.Newf("%w", err)
		}
		identities = append(identities, identity)
		identitiesByFingerprint[ssh.FingerprintSHA256(key.PublicKey().ToSsh())] = identity
	}
	return &AgeSshIdentities{identities: identities, identitiesByFingerprint: identitiesByFingerprint}, nil
}

// DecryptForFingerprint restricts decryption to the identity with the given
// SSH fingerprint instead of trying every configured identity.
func (this *AgeSshIdentities) DecryptForFingerprint(input io.Reader, fingerprint string) (io.Reader, error) {
	if this == nil || len(this.identitiesByFingerprint) == 0 {
		return nil, errors.System.Newf("no age SSH identities")
	}
	if input == nil {
		return nil, errors.System.Newf("nil age ciphertext input")
	}
	identity, exists := this.identitiesByFingerprint[fingerprint]
	if !exists {
		return nil, errors.Config.Newf("age SSH identity fingerprint %s is not available", fingerprint)
	}
	reader, err := age.Decrypt(input, identity)
	if err != nil {
		return nil, errors.System.Newf("%w", err)
	}
	return ageSshDecryptReader{Reader: reader}, nil
}

func (this *AgeSshIdentities) Decrypt(input io.Reader) (io.Reader, error) {
	if this == nil || len(this.identities) == 0 {
		return nil, errors.System.Newf("no age SSH identities")
	}
	if input == nil {
		return nil, errors.System.Newf("nil age ciphertext input")
	}
	reader, err := age.Decrypt(input, this.identities...)
	if err != nil {
		return nil, errors.Config.Newf("%w", err)
	}
	return ageSshDecryptReader{Reader: reader}, nil
}

type ageSshEncryptWriter struct {
	io.WriteCloser
}

func (this ageSshEncryptWriter) Write(value []byte) (int, error) {
	written, err := this.WriteCloser.Write(value)
	if err != nil {
		return written, errors.System.Newf("%w", err)
	}
	return written, nil
}

func (this ageSshEncryptWriter) Close() error {
	if err := this.WriteCloser.Close(); err != nil {
		return errors.System.Newf("%w", err)
	}
	return nil
}

type ageSshDecryptReader struct {
	io.Reader
}

func (this ageSshDecryptReader) Read(value []byte) (int, error) {
	read, err := this.Reader.Read(value)
	if err != nil && err != io.EOF {
		return read, errors.System.Newf("%w", err)
	}
	return read, err
}
