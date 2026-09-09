package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestKeysAppliesRestrictionsToCertificateSubjectAndAuthority(t *testing.T) {
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authority, err := gossh.NewSignerFromKey(authorityPrivate)
	require.NoError(t, err)
	subjectPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	subject, err := gossh.NewSignerFromKey(subjectPrivate)
	require.NoError(t, err)
	certificate := &gossh.Certificate{Key: subject.PublicKey()}
	require.NoError(t, certificate.SignCert(rand.Reader, authority))

	var keys Keys
	require.NoError(t, keys.SetDefaults())
	keys.RsaRestriction = crypto.RsaRestrictionAll
	allowed, err := keys.KeyAllowed(certificate)
	require.NoError(t, err)
	require.True(t, allowed)

	keys.RsaRestriction = crypto.RsaRestrictionNone
	allowed, err = keys.KeyAllowed(certificate)
	require.NoError(t, err)
	require.False(t, allowed, "the certificate subject must satisfy the restrictions")

	keys.RsaRestriction = crypto.RsaRestrictionAll
	keys.Ed25519Restriction = crypto.Ed25519RestrictionNone
	allowed, err = keys.KeyAllowed(certificate)
	require.NoError(t, err)
	require.False(t, allowed, "the certificate authority must satisfy the restrictions")
}
