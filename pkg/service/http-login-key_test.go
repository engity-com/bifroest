package service

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestWebKeyProofRejectsSha1TrailingDataAndWeakRsa(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	wire := base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal())
	key, err := parseWebPublicKey(wire)
	require.NoError(t, err)
	challenge := []byte("bifroest-http-public-key-v1\x00specific-attempt")
	for _, algorithm := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		signature, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, challenge, algorithm)
		require.NoError(t, err)
		encoded := base64.StdEncoding.EncodeToString(ssh.Marshal(signature))
		require.NoError(t, verifyWebKeyProof(key, challenge, encoded))
		require.Error(t, verifyWebKeyProof(key, []byte("other-attempt"), encoded))
		signature.Rest = []byte("trailing data")
		require.Error(t, verifyWebKeyProof(key, challenge, base64.StdEncoding.EncodeToString(ssh.Marshal(signature))))
	}
	legacy, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, challenge, ssh.KeyAlgoRSA)
	require.NoError(t, err)
	require.Error(t, verifyWebKeyProof(key, challenge, base64.StdEncoding.EncodeToString(ssh.Marshal(legacy))))
	for _, bits := range []uint{1024, 8193} {
		weak, err := ssh.NewPublicKey(&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), bits-1), E: 65537})
		require.NoError(t, err)
		_, err = parseWebPublicKey(base64.StdEncoding.EncodeToString(weak.Marshal()))
		require.Error(t, err)
	}
	for _, invalid := range []string{"-----BEGIN PRIVATE KEY-----", "ssh-ed25519 not-wire-format", wire + "\n"} {
		_, err := parseWebPublicKey(invalid)
		require.Error(t, err)
	}
}

func TestWebUserCertificateChecksRunAfterPossessionProof(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "wrong principal", "host certificate", "unsupported critical option"} {
		t.Run(mode, func(t *testing.T) {
			ca, signer := webLoginTestSigner(t), webLoginTestSigner(t)
			cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
			switch mode {
			case "expired":
				cert.ValidBefore = uint64(time.Now().Add(-time.Second).Unix())
			case "wrong principal":
				cert.ValidPrincipals = []string{"other"}
			case "host certificate":
				cert.CertType = ssh.HostCert
			case "unsupported critical option":
				cert.CriticalOptions = map[string]string{"force-command": "not enabled by the existing checker"}
			}
			require.NoError(t, cert.SignCert(rand.Reader, ca))
			certSigner, err := ssh.NewCertSigner(cert, signer)
			require.NoError(t, err)
			svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys("cert-authority " + string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
			})
			token := startWebAttempt(t, handler, "public-key", "alice", "Work", cert)
			step := waitWebLoginStep(t, handler, token, "Work")
			require.Zero(t, webSessionCount(t, svc))
			require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, signWebChallenge(t, certSigner, step)).Code)
			result := finishWebAttempt(t, handler, token, "Work")
			if mode != "valid" {
				require.Equal(t, http.StatusUnauthorized, result.Code)
				require.Zero(t, webSessionCount(t, svc))
				return
			}
			access := webTestAccess(t, svc, webTestToken(t, result), "Work")
			policy := authorization.AuthorizedKeyPolicyOf(access.auth)
			require.NotNil(t, policy)
			require.Nil(t, policy.ForcedCommand)
			require.True(t, policy.PtyAllowed)
			require.False(t, policy.PortForwardingAllowed)
		})
	}
}

func TestWebPublishedKeyRejectionDoesNotFallThrough(t *testing.T) {
	signer := webLoginTestSigner(t)
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		fixed := conf.Flows[0]
		fixed.DiscoverAsSlug = "Private"
		fallback := fixed
		fallback.Name = "fallback"
		fallback.DiscoverAsSlug = ""
		fallback.Authorization.V = &configuration.AuthorizationNone{}
		conf.Flows = configuration.Flows{fixed, fallback}
	})
	token := startWebAttempt(t, handler, "public-key", "alice", "Private", signer.PublicKey())
	step := waitWebLoginStep(t, handler, token, "Private")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Private", step, signWebChallenge(t, signer, step)).Code)
	require.Equal(t, http.StatusUnauthorized, finishWebAttempt(t, handler, token, "Private").Code)
	require.Zero(t, webSessionCount(t, svc))
}
