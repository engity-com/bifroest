package https

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Dummy material is generated only for an explicit configuration flag, stays in
// memory and is never a fallback, ACME account key or installed trust anchor.
func newDummyCertificate(domains []string, now time.Time) (*preparedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate ephemeral dummy key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("cannot generate dummy certificate serial")
	}
	serial.SetBit(serial, 0, 1)
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Bifroest explicit dummy certificate - testing only"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	for _, domain := range domains {
		if address, err := netip.ParseAddr(strings.Trim(domain, "[]")); err == nil {
			certificate.IPAddresses = append(certificate.IPAddresses, net.IP(address.AsSlice()))
		} else {
			certificate.DNSNames = append(certificate.DNSNames, domain)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("cannot sign ephemeral dummy certificate")
	}
	return validateCertificate(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, now)
}
