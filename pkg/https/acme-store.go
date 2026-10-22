package https

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
)

const maximumACMEStateBytes = 2 << 20

type acmeStore struct {
	base      *os.File
	baseInfo  os.FileInfo
	directory *os.File
	info      os.FileInfo
	path      string
}

func openACMEStore(path, directoryURL string) (*acmeStore, error) {
	canonical, err := sys.CanonicalPath(path)
	if err != nil {
		return nil, &materialError{"cannot resolve private ACME storage", err}
	}
	base, err := bfcrypto.EnsurePrivateDirectory(canonical)
	if err != nil {
		return nil, &materialError{"cannot open private ACME storage", err}
	}
	baseInfo, err := base.Stat()
	if err != nil {
		_ = base.Close()
		return nil, &materialError{"cannot inspect private ACME storage", err}
	}
	// Accounts and cached certificates must not silently cross CA boundaries.
	scope := filepath.Join(canonical, fmt.Sprintf("ca-%x", sha256.Sum256([]byte(directoryURL))))
	directory, err := bfcrypto.EnsurePrivateDirectory(scope)
	if err != nil {
		_ = base.Close()
		return nil, &materialError{"cannot open CA-scoped ACME storage", err}
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		_ = base.Close()
		return nil, &materialError{"cannot inspect ACME storage", err}
	}
	return &acmeStore{base: base, baseInfo: baseInfo, directory: directory, info: info, path: scope}, nil
}

func (this *acmeStore) check() error {
	if err := checkACMEDirectory(this.base.Name(), this.baseInfo); err != nil {
		return err
	}
	return checkACMEDirectory(this.path, this.info)
}

func checkACMEDirectory(path string, expected os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil {
		return &materialError{"cannot inspect ACME storage", err}
	}
	if !info.IsDir() || !os.SameFile(expected, info) {
		return fmt.Errorf("ACME storage directory was replaced")
	}
	// Recheck permissions/ACLs without repairing existing state.
	directory, err := bfcrypto.EnsurePrivateDirectory(path)
	if err != nil {
		return &materialError{"ACME storage is no longer private", err}
	}
	opened, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return &materialError{"cannot inspect open ACME storage", err}
	}
	if !os.SameFile(expected, opened) {
		_ = directory.Close()
		return fmt.Errorf("ACME storage directory changed during inspection")
	}
	if err := directory.Close(); err != nil {
		return &materialError{"cannot close ACME storage inspection", err}
	}
	return nil
}

func (this *acmeStore) close() error { return errors.Join(this.directory.Close(), this.base.Close()) }

func (this *acmeStore) read(name string) ([]byte, error) {
	if err := this.check(); err != nil {
		return nil, err
	}
	raw, err := bfcrypto.ReadSecurePrivateFile(filepath.Join(this.path, name), maximumACMEStateBytes)
	if err != nil {
		return nil, &materialError{"cannot read protected ACME state", err}
	}
	if err := this.check(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (this *acmeStore) write(ctx context.Context, name string, raw []byte, replace bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(raw) > maximumACMEStateBytes {
		return fmt.Errorf("ACME state exceeds its size limit")
	}
	if err := this.check(); err != nil {
		return err
	}
	if replace {
		// Never replace an existing foreign, linked or insecure cache file.
		if _, err := this.read(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := bfcrypto.WriteBootstrapFile(filepath.Join(this.path, name), raw, replace); err != nil {
		return &materialError{"cannot persist protected ACME state", err}
	}
	return this.check()
}

func (this *acmeStore) accountKey(ctx context.Context) (crypto.Signer, error) {
	const name = "account.pem"
	raw, err := this.read(name)
	if errors.Is(err, fs.ErrNotExist) {
		entries, readErr := os.ReadDir(this.path)
		if readErr != nil {
			return nil, &materialError{"cannot inspect existing ACME state", readErr}
		}
		if len(entries) != 0 {
			// Another process may just have installed the shared account key.
			if existing, readErr := this.read(name); readErr == nil {
				return parseACMEAccountKey(existing)
			}
			return nil, fmt.Errorf("ACME account key is missing while stored state exists; refusing account replacement")
		}
		key, createErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if createErr != nil {
			return nil, createErr
		}
		raw, createErr = marshalPrivateKey(key)
		if createErr != nil {
			return nil, createErr
		}
		if createErr = this.write(ctx, name, raw, false); errors.Is(createErr, fs.ErrExist) {
			raw, err = this.read(name)
		} else if createErr != nil {
			return nil, createErr
		} else {
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	return parseACMEAccountKey(raw)
}

func parseACMEAccountKey(raw []byte) (crypto.Signer, error) {
	block, rest, decodeErr := decodeACMEPEM(raw, "PRIVATE KEY")
	if decodeErr != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid stored ACME account key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &materialError{"invalid stored ACME account key", err}
	}
	if key, ok := key.(*ecdsa.PrivateKey); ok && key.Curve == elliptic.P256() {
		return key, nil
	}
	return nil, fmt.Errorf("stored ACME account key must be ECDSA P-256")
}

func marshalPrivateKey(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, &materialError{"cannot encode ACME private key", err}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func certificateStateName(domain string) string {
	return fmt.Sprintf("certificate-%x.pem", sha256.Sum256([]byte(domain)))
}

func (this *acmeStore) certificate(domain string) (*preparedCertificate, error) {
	raw, err := this.read(certificateStateName(domain))
	if err != nil {
		return nil, err
	}
	block, rest, err := decodeACMEPEM(raw, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &materialError{"invalid stored ACME private key", err}
	}
	certificate := tls.Certificate{PrivateKey: key}
	for len(bytes.TrimSpace(rest)) != 0 {
		block, rest, err = decodeACMEPEM(rest, "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		if len(certificate.Certificate) > maximumCertificateChainLength {
			return nil, fmt.Errorf("stored ACME certificate chain is too long")
		}
	}
	// Verify even expired cached material structurally before deciding to renew.
	var start, end time.Time
	if len(certificate.Certificate) == 0 || len(certificate.Certificate) > maximumCertificateChainLength {
		return nil, fmt.Errorf("invalid stored ACME certificate chain length")
	}
	for index, der := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &materialError{"invalid stored ACME certificate chain", err}
		}
		if index == 0 || parsed.NotBefore.After(start) {
			start = parsed.NotBefore
		}
		if index == 0 || parsed.NotAfter.Before(end) {
			end = parsed.NotAfter
		}
	}
	if !start.Before(end) {
		return nil, fmt.Errorf("stored ACME certificate chain has no valid lifetime")
	}
	checked, err := validateCertificate(&certificate, start)
	if err != nil {
		return nil, err
	}
	if !certificateMatches(checked.value, domain) {
		return nil, fmt.Errorf("stored ACME certificate does not match its requested domain")
	}
	leaf := checked.value.Leaf
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return nil, fmt.Errorf("stored ACME certificate identifiers differ from the requested DNS domain")
	}
	return checked, nil
}

func decodeACMEPEM(raw []byte, expected string) (*pem.Block, []byte, error) {
	raw = bytes.TrimSpace(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN "+expected+"-----")) {
		return nil, nil, fmt.Errorf("unexpected data in stored ACME PEM state")
	}
	marker := []byte("-----END " + expected + "-----")
	end := bytes.Index(raw, marker)
	if end < 0 {
		return nil, nil, fmt.Errorf("unterminated stored ACME PEM block")
	}
	end += len(marker)
	if bytes.Count(raw[:end], []byte("-----BEGIN ")) != 1 {
		return nil, nil, fmt.Errorf("nested stored ACME PEM block")
	}
	block, leftover := pem.Decode(raw[:end])
	if block == nil || block.Type != expected || len(block.Headers) != 0 || len(bytes.TrimSpace(leftover)) != 0 {
		return nil, nil, fmt.Errorf("invalid stored ACME PEM block")
	}
	return block, raw[end:], nil
}

func (this *acmeStore) putCertificate(ctx context.Context, domain string, certificate *tls.Certificate) error {
	raw, err := marshalPrivateKey(certificate.PrivateKey)
	if err != nil {
		return err
	}
	for _, der := range certificate.Certificate {
		raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return this.write(ctx, certificateStateName(domain), raw, true)
}
