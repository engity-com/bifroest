package protocol

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
)

func generateCertificateForPrivateKey(name string, prv crypto.Signer) (*x509.Certificate, error) {
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
	if _, isRSA := prv.(*rsa.PrivateKey); isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
		return failf("cannot generate serialNumer: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, prv.Public(), prv)
	if err != nil {
		return failf("cannot create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return failf("cannot parse just created certificate: %w", err)
	}

	return cert, nil
}

func peerVerifierForPublicKey(expected crypto.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no remote certificates presented  -> rejecting")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse remote certificate: %s -> rejecting", err)
		}
		if !reflect.DeepEqual(cert.PublicKey, expected) {
			return fmt.Errorf("remote certificate does not match expected -> rejecting")
		}
		return nil
	}
}

func alwaysWaysPeerVerifier(_ [][]byte, _ [][]*x509.Certificate) error {
	return fmt.Errorf("not initialized -> rejecting")
}
