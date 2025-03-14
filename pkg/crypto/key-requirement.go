package crypto

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/common"
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

	_ = os.MkdirAll(filepath.Dir(fn), 0700)
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0400)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseError(f)

	if err := WriteSshPrivateKey(pk, f); err != nil {
		return nil, fmt.Errorf("cannot write new private key to %q: %w", fn, err)
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
