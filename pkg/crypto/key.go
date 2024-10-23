package crypto

import (
	"bytes"
	gocrypto "crypto"
	"crypto/dsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/sys"
)

func ParsePublicKeyBytes(in []byte) (PublicKey, error) {
	v, err := ssh.ParsePublicKey(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIllegalSshKey, err)
	}
	return PublicKeyFromSsh(v)
}

func PublicKeyFromSsh(in ssh.PublicKey) (PublicKey, error) {
	result := publicKeySshWrapper{
		PublicKey: in,
	}
	if v, ok := in.(ssh.CryptoPublicKey); ok {
		result.sdk = v.CryptoPublicKey()
	} else {
		return nil, fmt.Errorf("%v does not implement %T", in, (ssh.CryptoPublicKey)(nil))
	}

	return &result, nil
}

func PublicKeyFromSdk(in gocrypto.PublicKey) (PublicKey, error) {
	s, err := ssh.NewPublicKey(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIllegalSshKey, err)
	}
	return &publicKeySshWrapper{
		PublicKey: s,
		sdk:       in,
	}, nil
}

type PublicKey interface {
	Type() string
	Marshal() []byte
	ToSsh() ssh.PublicKey
	ToSdk() gocrypto.PublicKey
	IsEqualTo(PublicKey) bool
}

type publicKeySshWrapper struct {
	ssh.PublicKey
	sdk gocrypto.PublicKey
}

func (this *publicKeySshWrapper) ToSsh() ssh.PublicKey {
	return this.PublicKey
}

func (this *publicKeySshWrapper) ToSdk() gocrypto.PublicKey {
	return this.sdk
}

func (this *publicKeySshWrapper) String() string {
	return this.Type() + " " + base64.StdEncoding.EncodeToString(this.Marshal())
}

func (this *publicKeySshWrapper) IsEqualTo(other PublicKey) bool {
	if other == nil {
		return false
	}
	tSsh, oSsh := this.ToSsh(), other.ToSsh()
	if tSsh.Type() != oSsh.Type() {
		return false
	}
	if !bytes.Equal(tSsh.Marshal(), oSsh.Marshal()) {
		return false
	}
	return true
}

func PrivateKeyFromSdk(sdk gocrypto.Signer) (PrivateKey, error) {
	v, err := ssh.NewSignerFromKey(sdk)
	if err != nil {
		return nil, err
	}
	return &privateKeyWrapper{publicKeySshWrapper{v.PublicKey(), sdk.Public()}, v, sdk}, nil
}

type PrivateKey interface {
	Type() string
	PublicKey() PublicKey
	ToSsh() ssh.Signer
	ToSdk() gocrypto.Signer
	MarshalPemBlock() (*pem.Block, error)
}

type privateKeyWrapper struct {
	pub publicKeySshWrapper
	ssh ssh.Signer
	sdk gocrypto.Signer
}

func (this *privateKeyWrapper) Type() string {
	return this.pub.Type()
}

func (this *privateKeyWrapper) PublicKey() PublicKey {
	return &this.pub
}

func (this *privateKeyWrapper) ToSsh() ssh.Signer {
	return this.ssh
}

func (this *privateKeyWrapper) ToSdk() gocrypto.Signer {
	return this.sdk
}

func (this *privateKeyWrapper) MarshalPemBlock() (*pem.Block, error) {
	switch v := this.sdk.(type) {
	case ed25519.PrivateKey:
		return &pem.Block{
			Type:    "OPENSSH PRIVATE KEY",
			Headers: nil,
			Bytes:   edkey.MarshalED25519PrivateKey(v),
		}, nil
	default:
		return ssh.MarshalPrivateKey(this.sdk, "")
	}
}

func (this *privateKeyWrapper) String() string {
	return this.pub.String()
}

func EnsureKeyFile(fn string, reqOnAbsence *KeyRequirement, rand io.Reader) (PrivateKey, error) {
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

	return PrivateKeyFromSdk(pk.(gocrypto.Signer))
}

func WriteSshPrivateKey(pk PrivateKey, to io.Writer) error {
	pb, err := pk.MarshalPemBlock()
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

func (this *dsaPrivateKey) Public() gocrypto.PublicKey {
	return this.PublicKey
}

func (this *dsaPrivateKey) Sign(rand io.Reader, digest []byte, _ gocrypto.SignerOpts) ([]byte, error) {
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
