// Package https contains the server-side HTTPS transport foundation. It is not
// part of the portable browser client and does not implement authentication.
package https

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	maximumCertificateFileBytes   = 1 << 20
	maximumCertificateChainLength = 16
)

type preparedCertificate struct {
	value     *tls.Certificate
	notBefore time.Time
	notAfter  time.Time
}

func (this *preparedCertificate) validAt(now time.Time) bool {
	return this != nil && !now.Before(this.notBefore) && now.Before(this.notAfter)
}

// materialError intentionally preserves a typed cause without including file
// paths, PEM data or parser diagnostics in log-safe error messages.
type materialError struct {
	operation string
	cause     error
}

func (this *materialError) Error() string { return this.operation + " (details redacted)" }
func (this *materialError) Unwrap() error { return this.cause }

func loadCertificate(configured configuration.HttpCertificate, now time.Time) (*preparedCertificate, error) {
	keyPath, err := sys.CanonicalPath(configured.PrivateKeyFile)
	if err != nil {
		return nil, &materialError{"cannot resolve TLS private key", err}
	}
	key, err := bfcrypto.LoadSecurePrivateKeyFile(keyPath, maximumCertificateFileBytes)
	if err != nil {
		return nil, &materialError{"cannot load protected TLS private key", err}
	}
	chain, err := readCertificateChain(configured.CertificateFile)
	if err != nil {
		return nil, &materialError{"cannot load TLS certificate chain", err}
	}
	certificate := &tls.Certificate{Certificate: chain, PrivateKey: key.ToSdk()}
	return validateCertificate(certificate, now)
}

func readCertificateChain(path string) ([][]byte, error) {
	// Reject non-regular or oversized configured inputs before opening them.
	canonical, err := sys.CanonicalPath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumCertificateFileBytes {
		return nil, fmt.Errorf("certificate must be a bounded regular file")
	}
	file, err := os.Open(canonical)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("certificate changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumCertificateFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximumCertificateFileBytes {
		return nil, fmt.Errorf("certificate file is too large")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("certificate changed while reading")
	}
	var chain [][]byte
	for raw = bytes.TrimSpace(raw); len(raw) != 0; raw = bytes.TrimSpace(raw) {
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("expected only certificate PEM blocks")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(raw, endMarker)
		if end < 0 {
			return nil, fmt.Errorf("unterminated certificate PEM block")
		}
		end += len(endMarker)
		block, rest := pem.Decode(raw[:end])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("invalid certificate PEM block")
		}
		chain = append(chain, block.Bytes)
		if len(chain) > maximumCertificateChainLength {
			return nil, fmt.Errorf("certificate chain is too long")
		}
		raw = raw[end:]
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}
	return chain, nil
}

// validateCertificate verifies the supplied chain against its last explicitly
// supplied certificate, not the host OS/public root store. Browser trust and
// revocation checks remain the client's responsibility, including private CAs.
func validateCertificate(certificate *tls.Certificate, now time.Time) (*preparedCertificate, error) {
	if certificate == nil || len(certificate.Certificate) == 0 || len(certificate.Certificate) > maximumCertificateChainLength {
		return nil, fmt.Errorf("empty or excessive TLS certificate chain")
	}
	signer, err := certificateSigner(certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, len(certificate.Certificate))
	result := *certificate
	result.Certificate = make([][]byte, len(chain))
	var totalBytes int
	var notBefore, notAfter time.Time
	for index, encoded := range certificate.Certificate {
		totalBytes += len(encoded)
		if totalBytes > maximumCertificateFileBytes {
			return nil, fmt.Errorf("TLS certificate chain is too large")
		}
		// Never trust a provider's cached Leaf or mutable backing byte slices.
		result.Certificate[index] = bytes.Clone(encoded)
		parsed, err := x509.ParseCertificate(result.Certificate[index])
		if err != nil {
			return nil, &materialError{"invalid TLS certificate", err}
		}
		if now.Before(parsed.NotBefore) {
			return nil, fmt.Errorf("TLS certificate [%d] is not valid yet", index)
		}
		if !now.Before(parsed.NotAfter) {
			return nil, fmt.Errorf("TLS certificate [%d] has expired", index)
		}
		chain[index] = parsed
		if index == 0 || parsed.NotBefore.After(notBefore) {
			notBefore = parsed.NotBefore
		}
		if index == 0 || parsed.NotAfter.Before(notAfter) {
			notAfter = parsed.NotAfter
		}
	}
	leaf := chain[0]
	if leaf.IsCA {
		return nil, fmt.Errorf("TLS leaf certificate must not be a CA")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("TLS leaf must permit digital signatures")
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("TLS RSA key must have at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, fmt.Errorf("TLS ECDSA key must have at least 256 bits")
		}
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported TLS public key algorithm")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, &materialError{"invalid TLS private key public component", err}
	}
	if !bytes.Equal(publicKey, leaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("TLS certificate and private key do not match")
	}
	for index := 0; index+1 < len(chain); index++ {
		if err := chain[index].CheckSignatureFrom(chain[index+1]); err != nil {
			return nil, &materialError{"invalid TLS certificate chain signature or order", err}
		}
	}
	if len(chain) == 1 && bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			return nil, &materialError{"invalid self-signed TLS certificate", err}
		}
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	for index := 1; index+1 < len(chain); index++ {
		intermediates.AddCert(chain[index])
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, &materialError{"TLS certificate chain is not valid for server authentication", err}
	}
	result.Leaf = leaf
	return &preparedCertificate{value: &result, notBefore: notBefore, notAfter: notAfter}, nil
}

func certificateSigner(value any) (crypto.Signer, error) {
	signer, ok := value.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("TLS private key cannot sign")
	}
	v := reflect.ValueOf(signer)
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Slice) && v.IsNil() {
		return nil, fmt.Errorf("TLS private key is nil")
	}
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid TLS Ed25519 private key length")
		}
	case *ed25519.PrivateKey:
		if len(*key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid TLS Ed25519 private key length")
		}
	}
	return signer, nil
}

func certificateMatches(certificate *tls.Certificate, domain string) bool {
	return certificate != nil && certificate.Leaf != nil && certificate.Leaf.VerifyHostname(strings.Trim(domain, "[]")) == nil
}
