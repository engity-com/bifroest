package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

type AgeSshRecipient struct {
	recipient   age.Recipient
	fingerprint string
}

func NewAgeSshRecipient(key ssh.PublicKey) (*AgeSshRecipient, error) {
	if key == nil {
		return nil, fmt.Errorf("nil SSH public key for age recipient")
	}
	var recipient age.Recipient
	var err error
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		recipient, err = agessh.NewEd25519Recipient(key)
	case ssh.KeyAlgoRSA:
		recipient, err = agessh.NewRSARecipient(key)
	default:
		err = fmt.Errorf("SSH public key type %q cannot be used as an age recipient", key.Type())
	}
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("nil age SSH recipient")
	}
	if output == nil {
		return nil, fmt.Errorf("nil age encryption output")
	}
	return age.Encrypt(output, this.recipient)
}

type AgeSshIdentities struct {
	identities []age.Identity
}

func NewAgeSshIdentities(keys []PrivateKey) (*AgeSshIdentities, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no age SSH identities")
	}
	identities := make([]age.Identity, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("nil age SSH identity")
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
			err = fmt.Errorf("SSH private key type %q cannot be used as an age identity", key.Type())
		}
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return &AgeSshIdentities{identities: identities}, nil
}

func (this *AgeSshIdentities) Decrypt(input io.Reader) (io.Reader, error) {
	if this == nil || len(this.identities) == 0 {
		return nil, fmt.Errorf("no age SSH identities")
	}
	if input == nil {
		return nil, fmt.Errorf("nil age ciphertext input")
	}
	return age.Decrypt(input, this.identities...)
}
