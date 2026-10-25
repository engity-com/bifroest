package crypto

import (
	gocrypto "crypto"
	"crypto/dsa"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/sys"
)

type PublicKey = keydata.PublicKey
type PrivateKey = keydata.PrivateKey

func ParsePublicKeyBytes(in []byte) (PublicKey, error)          { return keydata.ParsePublicKeyBytes(in) }
func PublicKeyFromSsh(in ssh.PublicKey) (PublicKey, error)      { return keydata.PublicKeyFromSsh(in) }
func PublicKeyFromSdk(in gocrypto.PublicKey) (PublicKey, error) { return keydata.PublicKeyFromSdk(in) }
func PrivateKeyFromSdk(in gocrypto.Signer) (PrivateKey, error)  { return keydata.PrivateKeyFromSdk(in) }
func WriteSshPrivateKey(pk PrivateKey, to io.Writer) error      { return keydata.WriteSshPrivateKey(pk, to) }

// Native file creation/loading and DSA compatibility remain outside portable key
// values. Existing private-file ownership/mode/ACL/bootstrap guards are unchanged.
func EnsureKeyFile(fn string, reqOnAbsence *KeyRequirement, rand io.Reader) (PrivateKey, error) {
	raw, err := readPrivateKeyFile(fn)
	if sys.IsNotExist(err) {
		if reqOnAbsence == nil {
			return nil, fmt.Errorf("private key %q does not exist", fn)
		}
		created, createErr := reqOnAbsence.CreateFile(rand, fn)
		if errors.Is(createErr, fs.ErrExist) {
			return EnsureKeyFile(fn, nil, rand)
		}
		return created, createErr
	} else if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", fn, err)
	}
	pk, err := ParsePrivateKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %q: %w", fn, err)
	}
	return pk, nil
}

func ParsePrivateKeyBytes(raw []byte) (PrivateKey, error) {
	pk, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	switch value := pk.(type) {
	case *dsa.PrivateKey:
		return PrivateKeyFromSdk(&dsaPrivateKey{value})
	case gocrypto.Signer:
		return PrivateKeyFromSdk(value)
	default:
		return nil, fmt.Errorf("private key of type %T cannot be used as signer", pk)
	}
}

type dsaPrivateKey struct{ *dsa.PrivateKey }

func (this *dsaPrivateKey) Public() gocrypto.PublicKey { return this.PublicKey }
func (this *dsaPrivateKey) Sign(rand io.Reader, digest []byte, _ gocrypto.SignerOpts) ([]byte, error) {
	r, s, err := dsa.Sign(rand, this.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 40)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[20-len(rb):20], rb)
	copy(sig[40-len(sb):], sb)
	return sig, nil
}
