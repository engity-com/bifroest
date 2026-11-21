package https

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEndpointExpirationSnapshotUsesEffectiveChainDeadline(t *testing.T) {
	now := time.Now()
	endpoint := &Endpoint{tls: &TLS{certificates: map[string]*preparedCertificate{"app.example.org": {
		value: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(24 * time.Hour)}}, notAfter: now.Add(time.Hour),
	}}}}
	snapshot := endpoint.CertificateExpirations()
	require.Equal(t, now.Add(time.Hour), snapshot["app.example.org"])
	delete(snapshot, "app.example.org")
	require.Len(t, endpoint.CertificateExpirations(), 1, "snapshots must not expose mutable TLS state")
}
