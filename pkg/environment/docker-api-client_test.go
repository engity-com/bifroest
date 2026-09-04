package environment

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerConnectionReferenceUsesDefaultHost(t *testing.T) {
	actual, err := (dockerConnectionReference{}).toApiClient()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, actual.Close()) })

	assert.Equal(t, client.DefaultDockerHost, actual.DaemonHost())
}

func TestDockerConnectionReferenceUsesConfiguredTcpHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/_ping", request.URL.Path)
		writer.Header().Set("API-Version", "1.44")
		_, _ = writer.Write([]byte("OK"))
	}))
	t.Cleanup(server.Close)

	actual, err := (dockerConnectionReference{host: server.URL, apiVersion: "1.44"}).toApiClient()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, actual.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = actual.Ping(ctx)
	require.NoError(t, err)
}

func TestDockerConnectionReferenceUsesConfiguredUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not supported by this test on Windows")
	}

	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/_ping", request.URL.Path)
		writer.Header().Set("API-Version", "1.44")
		_, _ = writer.Write([]byte("OK"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, server.Shutdown(ctx))
	})

	actual, err := (dockerConnectionReference{
		host:       fmt.Sprintf("unix://%s", socket),
		apiVersion: "1.44",
	}).toApiClient()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, actual.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = actual.Ping(ctx)
	require.NoError(t, err)
}

func TestDockerConnectionReferenceUsesConfiguredTLSHost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/_ping", request.URL.Path)
		writer.Header().Set("API-Version", "1.44")
		_, _ = writer.Write([]byte("OK"))
	}))
	t.Cleanup(server.Close)

	certPath := t.TempDir()
	certificate := server.TLS.Certificates[0]
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(certPath, "ca.pem"), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	}), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(certPath, "cert.pem"), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	}), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(certPath, "key.pem"), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	}), 0600))

	actual, err := (dockerConnectionReference{
		host:       server.URL,
		apiVersion: "1.44",
		certPath:   certPath,
		tlsVerify:  true,
	}).toApiClient()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, actual.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = actual.Ping(ctx)
	require.NoError(t, err)
}
