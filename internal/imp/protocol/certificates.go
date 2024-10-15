package protocol

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

func generateCertificateForPrivateKey(name string, prv crypto.PrivateKey) (*x509.Certificate, error) {
	fail := func(err error) (*x509.Certificate, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*x509.Certificate, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	var err error
	template := x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 30),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if prv.Type() == "ssh-rsa" {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
		return failf("cannot generate serialNumer: %w", err)
	}

	sdk := prv.ToSdk()
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, sdk.Public(), sdk)
	if err != nil {
		return failf("cannot create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return failf("cannot parse just created certificate: %w", err)
	}

	return cert, nil
}

func peerVerifierForPublicKey(expected crypto.PublicKey) (func([][]byte, [][]*x509.Certificate) error, error) {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no remote certificates presented: rejecting")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse remote certificate: %v: rejecting", err)
		}
		pKey, err := crypto.PublicKeyFromSdk(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("illegal peer public key: %v: rejecting", err)
		}
		if !expected.IsEqualTo(pKey) {
			return fmt.Errorf("remote certificate does not match expected: rejecting (%v != %v)", expected, pKey)
		}
		return nil
	}, nil
}

func alwaysAcceptPeerVerifier(_ [][]byte, _ [][]*x509.Certificate) error {
	return nil
}

func alwaysRejectPeerVerifier(_ [][]byte, _ [][]*x509.Certificate) error {
	return fmt.Errorf("not initialized -> rejecting")
}
