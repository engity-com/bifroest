package https

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func newTlsTestProof(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client := &acme.Client{Key: key}
	certificate, err := client.TLSALPN01ChallengeCert("test-token", domain)
	require.NoError(t, err)
	return certificate
}

func TestTlsRejectsInactiveInvalidOrWrongDomainAlpnProofs(t *testing.T) {
	manager, err := NewTLS(newTlsTestConfiguration(t, "app.example.org"), certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) { return nil, nil }))
	require.NoError(t, err)
	defer manager.Close()
	valid := newTlsTestProof(t, "app.example.org")
	_, err = manager.installChallenge(context.Background(), "app.example.org", &valid)
	require.Error(t, err, "there is no active issuance")
	ordinary := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil).certificate
	wrongDomain := newTlsTestProof(t, "other.example.org")
	for _, proof := range []*tls.Certificate{nil, ordinary, &wrongDomain, {Certificate: valid.Certificate}} {
		_, err := validateChallenge(proof, "app.example.org", time.Now())
		require.Error(t, err)
	}
	checked, err := validateChallenge(&valid, "app.example.org", time.Now())
	require.NoError(t, err)
	require.NotNil(t, checked.Leaf)
	_, err = validateChallenge(&valid, "app.example.org", checked.Leaf.NotAfter)
	require.Error(t, err)
	// A forged parsed Leaf must not replace the signed bytes.
	wrongDomain.Leaf = &x509.Certificate{DNSNames: []string{"app.example.org"}}
	_, err = validateChallenge(&wrongDomain, "app.example.org", time.Now())
	require.Error(t, err)
}

func TestTlsAlpnProofRequiresAnExactCriticalSha256Identifier(t *testing.T) {
	proof := newTlsTestProof(t, "app.example.org")
	identifier := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	for _, test := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"not critical", func(leaf *x509.Certificate) {
			for i := range leaf.ExtraExtensions {
				if leaf.ExtraExtensions[i].Id.Equal(identifier) {
					leaf.ExtraExtensions[i].Critical = false
				}
			}
		}},
		{"wrong digest size", func(leaf *x509.Certificate) {
			for i := range leaf.ExtraExtensions {
				if leaf.ExtraExtensions[i].Id.Equal(identifier) {
					leaf.ExtraExtensions[i].Value, _ = asn1.Marshal(make([]byte, 31))
				}
			}
		}},
		{"trailing ASN1 bytes", func(leaf *x509.Certificate) {
			for i := range leaf.ExtraExtensions {
				if leaf.ExtraExtensions[i].Id.Equal(identifier) {
					leaf.ExtraExtensions[i].Value = append(leaf.ExtraExtensions[i].Value, 0)
				}
			}
		}},
		{"unknown critical extension", func(leaf *x509.Certificate) {
			leaf.ExtraExtensions = append(leaf.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf, err := x509.ParseCertificate(proof.Certificate[0])
			require.NoError(t, err)
			leaf.ExtraExtensions = append([]pkix.Extension(nil), leaf.Extensions...)
			for index := range leaf.ExtraExtensions {
				leaf.ExtraExtensions[index].Value = append([]byte(nil), leaf.ExtraExtensions[index].Value...)
			}
			test.mutate(leaf)
			key := proof.PrivateKey.(crypto.Signer)
			encoded, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
			require.NoError(t, err)
			_, err = validateChallenge(&tls.Certificate{Certificate: [][]byte{encoded}, PrivateKey: key}, "app.example.org", time.Now())
			require.Error(t, err)
		})
	}
}

func TestOldChallengeReleaseCannotRemoveANewerProof(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	first, second := newTlsTestProof(t, "app.example.org"), newTlsTestProof(t, "app.example.org")
	var manager *TLS
	var err error
	manager, err = NewTLS(newTlsTestConfiguration(t, "app.example.org"), certificateSourceFunc(func(_ context.Context, domain string, publish Challenge) (*tls.Certificate, error) {
		oldRelease, err := publish(&first)
		if err != nil {
			return nil, err
		}
		defer oldRelease()
		newRelease, err := publish(&second)
		if err != nil {
			return nil, err
		}
		defer newRelease()
		oldRelease()
		selected, err := manager.Config().GetConfigForClient(testClientHello(domain, acme.ALPNProto))
		if err != nil {
			return nil, err
		}
		require.Equal(t, second.Certificate, selected.Certificates[0].Certificate)
		return fixture.certificate, nil
	}))
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(context.Background()))
}
