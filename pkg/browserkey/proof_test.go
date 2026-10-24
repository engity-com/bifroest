package browserkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var testScope = Scope{Origin: "https://app.example.org:8443", Slug: "Work/Prod", User: ""}

const testConnectionID = "9c77b24c-62f4-44c2-aea3-771c75e5a107"

func testPrivateKey(t *testing.T, key any, encrypted bool) []byte {
	t.Helper()
	var block *pem.Block
	var err error
	if encrypted {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "private file comment", []byte("tab-only passphrase"))
	} else {
		block, err = ssh.MarshalPrivateKey(key, "private file comment")
	}
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func testEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

func testChallenge(t *testing.T, key *Key, expires time.Time) []byte {
	t.Helper()
	pub, err := ParsePublicKey(key.PublicKey())
	require.NoError(t, err)
	raw, err := NewChallenge(testScope, testConnectionID, pub, expires)
	require.NoError(t, err)
	return raw
}

func TestImportedKeysSignOriginalSshWireProof(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys := []any{testEd25519(t), rsaKey}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		keys = append(keys, key)
	}
	for _, private := range keys {
		for _, encrypted := range []bool{false, true} {
			original := testPrivateKey(t, private, encrypted)
			before := bytes.Clone(original)
			key, err := Import(original, []byte("tab-only passphrase"), nil, testScope)
			require.NoError(t, err)
			require.Equal(t, before, original, "import must not mutate caller-owned input")
			encoded, err := json.Marshal(key)
			require.NoError(t, err)
			require.Equal(t, "{}", string(encoded))
			expires := time.Now().Add(time.Minute)
			raw := testChallenge(t, key, expires)
			proof, err := key.Sign(base64.StdEncoding.EncodeToString(raw), expires)
			require.NoError(t, err)
			pub, err := ParsePublicKey(key.PublicKey())
			require.NoError(t, err)
			require.NoError(t, Verify(pub, raw, proof))
			wire, err := base64.StdEncoding.DecodeString(proof)
			require.NoError(t, err)
			var signature ssh.Signature
			require.NoError(t, ssh.Unmarshal(wire, &signature))
			if pub.Type() == ssh.KeyAlgoRSA {
				require.Equal(t, ssh.KeyAlgoRSASHA512, signature.Format, "RSA must never fall back to SHA-1")
			}
			_, err = key.Sign(base64.StdEncoding.EncodeToString(raw), expires)
			require.ErrorIs(t, err, ErrProof)
			require.ErrorIs(t, Verify(pub, append(raw, '\n'), proof), ErrProof, "original bytes are signed")
		}
	}
}

func TestImportPemFormatsAndStrictPrivateEnvelope(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(testEd25519(t))
	require.NoError(t, err)
	for _, block := range []*pem.Block{{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, {Type: "EC PRIVATE KEY", Bytes: ecDER}, {Type: "PRIVATE KEY", Bytes: pkcs8}} {
		key, err := Import(pem.EncodeToMemory(block), nil, nil, testScope)
		require.NoError(t, err)
		key.Close()
		_, err = key.Sign("must not sign after close", time.Now().Add(time.Minute))
		require.ErrorIs(t, err, ErrProof)
	}
	valid := testPrivateKey(t, testEd25519(t), false)
	for _, invalid := range [][]byte{nil, []byte("private diagnostic"), append(bytes.Clone(valid), valid...), append(bytes.Clone(valid), []byte("junk")...), append([]byte("junk\n"), valid...), bytes.Repeat([]byte("x"), MaxPrivateKeyBytes+1), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("not a supported PKCS8 container")})} {
		key, err := Import(invalid, nil, nil, testScope)
		require.Nil(t, key)
		require.ErrorIs(t, err, ErrImport)
		require.NotContains(t, err.Error(), "private diagnostic")
	}
	_, err = Import(testPrivateKey(t, testEd25519(t), true), []byte("wrong passphrase"), nil, testScope)
	require.ErrorIs(t, err, ErrImport)
	_, err = Import(valid, bytes.Repeat([]byte("x"), MaxPassphraseBytes+1), nil, testScope)
	require.ErrorIs(t, err, ErrImport)
}

func TestCertificateImportPinsExactWireKeyWithoutClaimingTrust(t *testing.T) {
	private := testEd25519(t)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	ca, err := ssh.NewSignerFromKey(testEd25519(t))
	require.NoError(t, err)
	// Expired/untrusted certs can be imported, but never become authority here.
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: uint64(time.Now().Add(-time.Hour).Unix())}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	certificate := ssh.MarshalAuthorizedKey(cert)
	key, err := Import(testPrivateKey(t, private, false), nil, certificate, testScope)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(cert.Marshal()), key.PublicKey())
	require.Equal(t, ssh.FingerprintSHA256(cert), key.Fingerprint())
	expires := time.Now().Add(time.Minute)
	raw := testChallenge(t, key, expires)
	proof, err := key.Sign(base64.StdEncoding.EncodeToString(raw), expires)
	require.NoError(t, err)
	require.NoError(t, Verify(cert, raw, proof))
	for _, invalid := range [][]byte{ssh.MarshalAuthorizedKey(signer.PublicKey()), append([]byte("restrict "), certificate...), append(bytes.Clone(certificate), certificate...), append([]byte("invalid line\n"), certificate...), bytes.Repeat([]byte("x"), MaxCertificateBytes+1)} {
		_, err := Import(testPrivateKey(t, private, false), nil, invalid, testScope)
		require.ErrorIs(t, err, ErrImport)
	}
	_, err = Import(testPrivateKey(t, testEd25519(t), false), nil, certificate, testScope)
	require.ErrorIs(t, err, ErrImport)
	cert.CertType = ssh.HostCert
	_, err = Import(testPrivateKey(t, private, false), nil, ssh.MarshalAuthorizedKey(cert), testScope)
	require.ErrorIs(t, err, ErrImport)
}

func TestKeyProofRejectsForeignMalformedAndExpiredChallengesOnce(t *testing.T) {
	private := testPrivateKey(t, testEd25519(t), false)
	for _, mode := range []string{"origin", "slug", "user", "connection", "key", "nonce", "expiry", "extended", "expired", "domain", "duplicate", "unknown", "null", "trailing", "oversized", "bad64"} {
		t.Run(mode, func(t *testing.T) {
			key, err := Import(private, nil, nil, testScope)
			require.NoError(t, err)
			now := time.Now()
			expires := now.Add(time.Minute)
			raw := testChallenge(t, key, expires)
			var selected challenge
			require.NoError(t, json.Unmarshal(raw[len(domain):], &selected))
			switch mode {
			case "origin":
				selected.Origin = "https://other.example.org:8443"
			case "slug":
				selected.Slug = "work/Prod"
			case "user":
				selected.User = "alice"
			case "connection":
				selected.ConnectionID = ""
			case "key":
				selected.PublicKey = "SHA256:foreign"
			case "nonce":
				selected.Nonce = "bad"
			case "expiry":
				selected.ExpiresAt = expires.Add(time.Second)
			case "extended":
				selected.ExpiresAt = now.Add(ChallengeLifetime + time.Second)
				expires = selected.ExpiresAt
			case "expired":
				selected.ExpiresAt = now
				expires = now
			}
			body, err := json.Marshal(selected)
			require.NoError(t, err)
			raw = append([]byte(domain), body...)
			switch mode {
			case "domain":
				raw[0] = 'X'
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"user":""`, `"user":"alice","user":""`, 1))
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `"user":""`, `"user":"","rights":"admin"`, 1))
			case "null":
				raw = []byte(strings.Replace(string(raw), `"user":""`, `"user":null`, 1))
			case "trailing":
				raw = append(raw, '\n')
			case "oversized":
				raw = bytes.Repeat([]byte("x"), 8193)
			}
			encoded := base64.StdEncoding.EncodeToString(raw)
			if mode == "bad64" {
				encoded += "\n"
			}
			proof, err := key.sign(encoded, expires, now)
			require.ErrorIs(t, err, ErrProof)
			require.Empty(t, proof)
			_, err = key.sign(base64.StdEncoding.EncodeToString(testChallenge(t, key, expires)), expires, now)
			require.ErrorIs(t, err, ErrProof, "an invalid request also consumes this imported key")
		})
	}
}

func TestConcurrentKeyProofSignsAtMostOnce(t *testing.T) {
	key, err := Import(testPrivateKey(t, testEd25519(t), false), nil, nil, testScope)
	require.NoError(t, err)
	expires := time.Now().Add(time.Minute)
	encoded := base64.StdEncoding.EncodeToString(testChallenge(t, key, expires))
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Go(func() { _, err := key.Sign(encoded, expires); results <- err })
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, ErrProof)
		}
	}
	require.Equal(t, 1, success)
}

func TestOpenSshResourceGuardRejectsUnboundedKdfBeforeDecryption(t *testing.T) {
	for _, rounds := range []uint32{0, MaxBcryptRounds + 1, ^uint32(0)} {
		envelope := struct {
			Cipher, KDF, Options string
			Keys                 uint32
			Public, Private      []byte
		}{"aes256-ctr", "bcrypt", string(ssh.Marshal(struct {
			Salt   []byte
			Rounds uint32
		}{[]byte("salt"), rounds})), 1, nil, nil}
		raw := append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)
		_, err := Import(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: raw}), []byte("secret"), nil, testScope)
		require.ErrorIs(t, err, ErrImport)
	}
}

func TestImportAndChallengeRejectInvalidScope(t *testing.T) {
	private := testPrivateKey(t, testEd25519(t), false)
	for _, scope := range []Scope{{Origin: "http://app.example.org"}, {Origin: "https://user:secret@app.example.org"}, {Origin: "https://app.example.org/"}, {Origin: testScope.Origin, Slug: "work/"}, {Origin: testScope.Origin, Slug: "one/two/three"}, {Origin: testScope.Origin, User: "alice\n"}, {Origin: testScope.Origin, User: strings.Repeat("€", 100)}} {
		_, err := Import(private, nil, nil, scope)
		require.ErrorIs(t, err, ErrImport)
	}
}

func TestChallengeKeepsExistingV1FieldOrderAndEncoding(t *testing.T) {
	key, err := Import(testPrivateKey(t, testEd25519(t), false), nil, nil, testScope)
	require.NoError(t, err)
	defer key.Close()
	expires := time.Now().Add(time.Minute)
	raw := testChallenge(t, key, expires)
	var selected challenge
	require.NoError(t, json.Unmarshal(raw[len(domain):], &selected))
	// Exact original service struct, without embedding the new Scope type.
	legacy := struct {
		Origin       string    `json:"origin"`
		Slug         string    `json:"slug"`
		User         string    `json:"user"`
		ConnectionId string    `json:"connectionId"`
		PublicKey    string    `json:"publicKeyFingerprint"`
		Nonce        string    `json:"nonce"`
		ExpiresAt    time.Time `json:"expiresAt"`
	}{testScope.Origin, testScope.Slug, testScope.User, testConnectionID, key.Fingerprint(), selected.Nonce, expires}
	body, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.Equal(t, append([]byte(domain), body...), raw)
}

func TestUninitializedKeyDoesNotSign(t *testing.T) {
	for _, key := range []*Key{nil, {}} {
		require.Empty(t, key.PublicKey())
		require.Empty(t, key.Fingerprint())
		key.Close()
		_, err := key.Sign("not a proof", time.Now().Add(time.Minute))
		require.ErrorIs(t, err, ErrProof)
	}
}
