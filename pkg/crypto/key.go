package crypto

import (
	"crypto"
	"crypto/dsa"
	"encoding/pem"
	"fmt"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
)

func EnsureKeyFile(fn string, reqOnAbsence *KeyRequirement, rand io.Reader) (crypto.Signer, error) {
	raw, err := os.ReadFile(fn)
	if sys.IsNotExist(err) {
		return reqOnAbsence.CreateFile(rand, fn)
	} else if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", fn, err)
	}

	pk, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %q: %w", fn, err)
	}

	return pk.(crypto.Signer), nil
}

func encodePrivateKeyToPemBlock(pk crypto.Signer) (*pem.Block, error) {
	if pk == nil {
		return nil, fmt.Errorf("nil private key")
	}
	switch v := pk.(type) {
	case ed25519.PrivateKey:
		return &pem.Block{
			Type:    "OPENSSH PRIVATE KEY",
			Headers: nil,
			Bytes:   edkey.MarshalED25519PrivateKey(v),
		}, nil
	default:
		return ssh.MarshalPrivateKey(pk, "")
	}
}

func WriteSshPrivateKey(pk crypto.Signer, to io.Writer) error {
	pb, err := encodePrivateKeyToPemBlock(pk)
	if err != nil {
		return fmt.Errorf("cannot encode private key: %w", err)
	}

	if err := pem.Encode(to, pb); err != nil {
		return fmt.Errorf("cannot write private key: %w", err)
	}

	return nil
}

type dsaPrivateKey struct {
	*dsa.PrivateKey
}

func (this *dsaPrivateKey) Public() crypto.PublicKey {
	return this.PublicKey
}

func (this *dsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := dsa.Sign(rand, this.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, 40)
	rb := r.Bytes()
	sb := s.Bytes()

	copy(sig[20-len(rb):20], rb)
	copy(sig[40-len(sb):], sb)

	return sig, nil
}
