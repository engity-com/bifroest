package crypto

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	DefaultKeyBitSize        = 4096
	DefaultDsaParameterSize  = dsa.L2048N256
	DefaultEllipticCurveType = EllipticCurveTypeP521
)

type KeyRequirement struct {
	Type KeyType

	// BitSize is used for RSA keys. Default is DefaultKeyBitSize
	BitSize *int

	// DsaParameterSize is used for KeyTypeDsa. Default is DefaultDsaParameterSize
	DsaParameterSize *dsa.ParameterSizes

	// EllipticCurveType is used for KeyTypeEcdsa. Default is DefaultEllipticCurveType
	EllipticCurveType *EllipticCurveType
}

func (this KeyRequirement) CreateFile(rand io.Reader, fn string) (PrivateKey, error) {
	pk, err := this.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	var content bytes.Buffer
	if err := WriteSshPrivateKey(pk, &content); err != nil {
		return nil, fmt.Errorf("cannot encode new private key for %q: %w", fn, err)
	}
	parent := filepath.Dir(fn)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, fmt.Errorf("cannot create parent directory for private key %q: %w", fn, err)
	}
	f, err := os.CreateTemp(parent, "."+filepath.Base(fn)+".tmp-*")
	if err != nil {
		return nil, err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err := preparePrivateKeyFile(f, temporary); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot protect new private key %q: %w", fn, err)
	}
	if _, err := f.Write(content.Bytes()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot write new private key to %q: %w", fn, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot flush new private key for %q: %w", fn, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("cannot close new private key for %q: %w", fn, err)
	}
	if err := installPrivateKeyFile(temporary, fn); err != nil {
		return nil, fmt.Errorf("cannot install new private key at %q: %w", fn, err)
	}

	return pk, nil
}

func (this KeyRequirement) GenerateKey(rand io.Reader) (PrivateKey, error) {
	done := func(s PrivateKey, err error) (PrivateKey, error) {
		if err != nil {
			return nil, fmt.Errorf("cannot gerate %v private key: %w", this.Type, err)
		}
		return s, nil
	}
	if rand == nil {
		rand = crand.Reader
	}
	switch this.Type {
	case KeyTypeRsa:
		return done(this.generateRsa(rand))
	case KeyTypeDsa:
		return done(this.generateDsa(rand))
	case KeyTypeEcdsa:
		return done(this.generateEcdsa(rand))
	case KeyTypeEd25519:
		return done(this.generateEd25519(rand))
	default:
		return nil, fmt.Errorf("illegal key type: %v", this.Type)
	}
}

func (this KeyRequirement) generateRsa(rand io.Reader) (PrivateKey, error) {
	bitSize := DefaultKeyBitSize
	if v := this.BitSize; v != nil {
		bitSize = *v
	}
	sdk, err := rsa.GenerateKey(rand, bitSize)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromSdk(sdk)
}

func (this KeyRequirement) generateDsa(rand io.Reader) (PrivateKey, error) {
	parameterSize := DefaultDsaParameterSize
	if v := this.DsaParameterSize; v != nil {
		parameterSize = *v
	}
	var pk dsa.PrivateKey

	if err := dsa.GenerateParameters(&pk.Parameters, rand, parameterSize); err != nil {
		return nil, err
	}

	if err := dsa.GenerateKey(&pk, rand); err != nil {
		return nil, err
	}

	return PrivateKeyFromSdk(&dsaPrivateKey{&pk})
}

func (this KeyRequirement) generateEcdsa(rand io.Reader) (PrivateKey, error) {
	curveType := DefaultEllipticCurveType
	if v := this.EllipticCurveType; v != nil {
		curveType = *v
	}

	curve, err := curveType.Curve()
	if err != nil {
		return nil, err
	}

	sdk, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromSdk(sdk)
}

func (this KeyRequirement) generateEd25519(rand io.Reader) (PrivateKey, error) {
	_, sdk, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromSdk(sdk)
}
