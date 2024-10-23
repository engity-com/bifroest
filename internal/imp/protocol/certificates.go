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
	"github.com/engity-com/bifroest/pkg/session"
)

func generateCertificateForPrivateKey(name string, sessionId session.Id, prv crypto.PrivateKey) (*x509.Certificate, error) {
	fail := func(err error) (*x509.Certificate, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*x509.Certificate, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	var extraNames []pkix.AttributeTypeAndValue
	if !sessionId.IsZero() {
		sessB, err := sessionId.MarshalText()
		if err != nil {
			return fail(err)
		}
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  crypto.ObjectIdSessionId.ToNativeDirect(),
			Value: string(sessB),
		})
	}

	var err error
	template := x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			CommonName: name,
			ExtraNames: extraNames,
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

func peerVerifierForSessionId(expected session.Id) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no remote certificates presented: rejecting")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse remote certificate: %v: rejecting", err)
		}
		for _, candidate := range cert.Subject.Names {
			if crypto.ObjectIdSessionId.IsEqualTo(candidate.Type) {
				if str, ok := candidate.Value.(string); ok {
					var buf session.Id
					if err := buf.Set(str); err == nil {
						if expected.IsEqualTo(buf) {
							return nil
						}
						return fmt.Errorf("peer certificate was issued for another sessionId: %v != %v: rejecting", expected, buf)
					}
				}
				return fmt.Errorf("peer certificate has extraName %v but no sessionId value: rejecting", crypto.ObjectIdSessionId)
			}
		}
		return fmt.Errorf("peer certificate has no %v extraName: rejecting", crypto.ObjectIdSessionId)
	}
}

func alwaysRejectPeerVerifier(_ [][]byte, _ [][]*x509.Certificate) error {
	return fmt.Errorf("not initialized -> rejecting")
}
