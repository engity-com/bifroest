package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestBrowserPublicKeyUiWasmLocalImportProofCertificatesAndRemember(t *testing.T) {
	testBrowserLoginUi(t, true, "key")
}

func TestBrowserPublicKeyAlgorithmsUiOpenShells(t *testing.T) {
	for _, algorithm := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(algorithm, func(t *testing.T) { testBrowserLoginUi(t, true, "key-"+algorithm) })
	}
}

func TestBrowserPublicKeyCertificateWithoutPtyUiCannotOpenShell(t *testing.T) {
	testBrowserLoginUi(t, true, "key-no-pty")
}

func TestBrowserPublicKeyUiSafeFailureDiagnostics(t *testing.T) {
	for _, phase := range []string{"module", "download", "worker", "crypto"} {
		t.Run(phase, func(t *testing.T) { testBrowserLoginUi(t, true, "key-diagnostic-"+phase) })
	}
}

func browserKeyUiFixture(t *testing.T) (string, bfcrypto.AuthorizedKeys) {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys := map[string]any{"ed": ed, "rsa": rsaKey}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		keys[name] = key
	}
	fixture := map[string]string{"passphrase": "tab-only fixture passphrase"}
	var authorized strings.Builder
	for name, key := range keys {
		signer, err := ssh.NewSignerFromKey(key)
		require.NoError(t, err)
		authorized.Write(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "private fixture comment", []byte(fixture["passphrase"]))
		require.NoError(t, err)
		fixture[name] = string(pem.EncodeToMemory(block))
	}
	plain, err := ssh.MarshalPrivateKey(ed, "private fixture comment")
	require.NoError(t, err)
	fixture["plain"] = string(pem.EncodeToMemory(plain))
	signer, err := ssh.NewSignerFromKey(ed)
	require.NoError(t, err)
	ca := webLoginTestSigner(t)
	authorized.WriteString("cert-authority " + string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	for name, expires := range map[string]time.Time{"certificate": time.Now().Add(time.Hour), "noPtyCertificate": time.Now().Add(time.Hour), "expiredCertificate": time.Now().Add(-time.Hour)} {
		cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: uint64(expires.Unix())}
		if name == "certificate" {
			cert.Permissions.Extensions = map[string]string{"permit-pty": ""}
		}
		require.NoError(t, cert.SignCert(rand.Reader, ca))
		fixture[name] = string(ssh.MarshalAuthorizedKey(cert))
	}
	encoded, err := json.Marshal(fixture)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "local-key-fixtures.json")
	require.NoError(t, os.WriteFile(file, encoded, 0600))
	return file, bfcrypto.AuthorizedKeys(authorized.String())
}
