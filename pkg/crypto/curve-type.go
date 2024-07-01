package crypto

import (
	"crypto/elliptic"
	"fmt"
)

type EllipticCurveType uint8

const (
	EllipticCurveTypeP224 EllipticCurveType = iota
	EllipticCurveTypeP256
	EllipticCurveTypeP384
	EllipticCurveTypeP521
)

func (this EllipticCurveType) String() string {
	switch this {
	case EllipticCurveTypeP224:
		return "P224"
	case EllipticCurveTypeP256:
		return "P256"
	case EllipticCurveTypeP384:
		return "P384"
	case EllipticCurveTypeP521:
		return "P521"
	default:
		return fmt.Sprintf("illegal-elliptic-curve-type-%d", this)
	}
}

func (this EllipticCurveType) Curve() (elliptic.Curve, error) {
	switch this {
	case EllipticCurveTypeP224:
		return elliptic.P224(), nil
	case EllipticCurveTypeP256:
		return elliptic.P256(), nil
	case EllipticCurveTypeP384:
		return elliptic.P384(), nil
	case EllipticCurveTypeP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("illegal elliptic curve type: %d", this)
	}
}
