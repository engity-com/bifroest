package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/browserkey"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestRealHttpsInteractiveAndKeyAttemptsOutliveTheirInitialRequest(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	ca := webLoginTestSigner(t)
	certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"restricted-key-user"}, ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	require.NoError(t, certificate.SignCert(rand.Reader, ca))
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "local-only fixture", []byte("tab-only passphrase"))
	require.NoError(t, err)
	localKey := pem.EncodeToMemory(block)
	var root *x509.Certificate
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:correct")
		entry := &conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
		entry.AuthorizedKeys = crypto.AuthorizedKeys(string(entry.AuthorizedKeys) + "\n" + string(ssh.MarshalAuthorizedKey(signer.PublicKey())) + "\ncert-authority " + string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Http = &configuration.Http{}
		require.NoError(t, conf.Http.SetDefaults())
		conf.Http.Enabled = true
		conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
		conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
		root = httpListenerTestCertificate(t, conf, nil)
	})
	client := server.mustDial(t)
	defer client.Close()
	source, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, source.Run("first"))
	svc := server.service
	require.NoError(t, svc.https.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- svc.https.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, svc.https.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(time.Second):
			t.Error("HTTPS did not stop")
		}
	})
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	httpsClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	// Reuse the JSON protocol helpers, but every request below traverses the real
	// TLS/HTTP2 server. No synthetic TLS metadata reaches the service handler.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "https://"+r.Host+r.URL.RequestURI(), r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "client error", 500)
			return
		}
		request.Header = r.Header.Clone()
		response, err := httpsClient.Do(request)
		if err != nil {
			t.Error(err)
			http.Error(w, "client error", 500)
			return
		}
		defer response.Body.Close()
		if response.ProtoMajor != 2 {
			t.Error("HTTP/2 was not negotiated")
		}
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	interactive := startWebAttempt(t, handler, "interactive", server.username, "Work", nil)
	step := waitWebLoginStep(t, handler, interactive, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, interactive, "Work", step, "correct").Code)
	one := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, handler, interactive, "Work")), "Work")
	key := startWebAttempt(t, handler, "public-key", server.username, "Work", server.signer.PublicKey())
	proof := waitWebLoginStep(t, handler, key, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, key, "Work", proof, signWebChallenge(t, server.signer, proof)).Code)
	two := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, handler, key, "Work")), "Work")
	require.Equal(t, one.auth.FindSession().Id(), two.auth.FindSession().Id())
	// The portable client core imports/decrypts locally. Neither the private
	// material nor passphrase is sent to the actual TLS/HTTP2 endpoint.
	for _, cert := range [][]byte{nil, ssh.MarshalAuthorizedKey(certificate)} {
		imported, err := browserkey.Import(localKey, []byte("tab-only passphrase"), cert, browserkey.Scope{Origin: "https://app.example.org", Slug: "Work", User: server.username})
		require.NoError(t, err)
		start := webAttemptRequest(handler, "public-key", "", map[string]string{"slug": "Work", "user": server.username, "publicKey": imported.PublicKey()})
		require.Equal(t, http.StatusAccepted, start.Code)
		var pending webLoginPending
		require.NoError(t, json.Unmarshal(start.Body.Bytes(), &pending))
		step := waitWebLoginStep(t, handler, pending.AttemptToken, "Work")
		signature, err := imported.Sign(step.Challenge, pending.ExpiresAt)
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, answerWebStep(handler, pending.AttemptToken, "Work", step, signature).Code)
		access := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, handler, pending.AttemptToken, "Work")), "Work")
		require.Equal(t, one.auth.FindSession().Id(), access.auth.FindSession().Id())
		imported.Close()
	}
	require.Equal(t, 1, webSessionCount(t, svc))
}
