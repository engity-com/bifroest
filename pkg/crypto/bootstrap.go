package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

const MaxBootstrapInputSize = 4 * 1024 * 1024

func ExportPublicKey(identityFile, comment string) ([]byte, error) {
	if strings.ContainsAny(comment, "\r\n") {
		return nil, fmt.Errorf("comment must not contain a line break")
	}
	key, err := EnsureKeyFile(identityFile, nil, nil)
	if err != nil {
		return nil, err
	}
	line := bytes.TrimSpace(MarshalPublicKey(key.PublicKey()))
	if comment != "" {
		line = append(append(line, ' '), comment...)
	}
	return append(line, '\n'), nil
}

func MarshalPublicKey(key PublicKey) []byte {
	return append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key.ToSsh())), '\n')
}

func ExportKnownHostKey(identityFile, address string) ([]byte, error) {
	key, err := EnsureKeyFile(identityFile, &KeyRequirement{Type: KeyTypeEd25519}, nil)
	if err != nil {
		return nil, err
	}
	return ExportKnownHostKeys([]PrivateKey{key}, address)
}

func ExportKnownHostKeys(keys []PrivateKey, address string) ([]byte, error) {
	resolvedAddress, err := bfssh.ParseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("illegal host address %q: %w", address, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH host key is available")
	}
	host := knownhosts.Normalize(resolvedAddress.String())
	var result []byte
	for i, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("nil SSH host key at index %d", i)
		}
		result = append(result, knownhosts.Line([]string{host}, key.PublicKey().ToSsh())...)
		result = append(result, '\n')
	}
	return result, nil
}

func ImportKnownHostsFile(path string, imported []byte, expectedFingerprint string) (int, error) {
	entries, err := parseImportedKnownHosts(imported)
	if err != nil {
		return 0, err
	}
	return mergeBootstrapTrustFile(path, entries, expectedFingerprint, parseExistingKnownHosts)
}

func ImportCertificateAuthoritiesFile(path string, imported []byte, expectedFingerprint string) (int, error) {
	entries, err := parseImportedCertificateAuthorities(imported)
	if err != nil {
		return 0, err
	}
	return mergeBootstrapTrustFile(path, entries, expectedFingerprint, parseExistingCertificateAuthorities)
}

type bootstrapTrustEntry struct {
	key        ssh.PublicKey
	line       []byte
	identities []string
}

type bootstrapTrustParser func([]byte) ([]bootstrapTrustEntry, error)

func mergeBootstrapTrustFile(path string, imported []bootstrapTrustEntry, expectedFingerprint string, parseExisting bootstrapTrustParser) (result int, rErr error) {
	if path == "" {
		return 0, fmt.Errorf("trust file path is empty")
	}
	if err := validateExpectedFingerprint(expectedFingerprint); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return 0, fmt.Errorf("cannot create parent directory for trust file %q: %w", path, err)
	}
	lock, err := acquireBootstrapFileLock(path + ".lock")
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := lock.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	existingRaw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("cannot read trust file %q: %w", path, err)
	}
	existing, err := parseExisting(existingRaw)
	if err != nil {
		return 0, fmt.Errorf("illegal existing trust file %q: %w", path, err)
	}
	known := make(map[string]struct{}, len(existing)+len(imported))
	for _, entry := range existing {
		for _, identity := range entry.identities {
			known[identity] = struct{}{}
		}
	}
	var additions []byte
	for _, entry := range imported {
		if expectedFingerprint != "" && ssh.FingerprintSHA256(entry.key) != expectedFingerprint {
			return 0, fmt.Errorf("public key fingerprint %s does not match expected fingerprint", ssh.FingerprintSHA256(entry.key))
		}
		allKnown := len(entry.identities) > 0
		for _, identity := range entry.identities {
			if _, found := known[identity]; !found {
				allKnown = false
				break
			}
		}
		if allKnown {
			continue
		}
		for _, identity := range entry.identities {
			known[identity] = struct{}{}
		}
		additions = append(additions, entry.line...)
		result++
	}
	if result == 0 {
		return 0, nil
	}
	merged := append([]byte(nil), existingRaw...)
	if len(merged) > 0 && merged[len(merged)-1] != '\n' {
		merged = append(merged, '\n')
	}
	merged = append(merged, additions...)
	if _, err := parseExisting(merged); err != nil {
		return 0, fmt.Errorf("cannot produce valid trust file %q: %w", path, err)
	}
	if err := WriteBootstrapFile(path, merged, true); err != nil {
		return 0, err
	}
	return result, nil
}

func parseImportedCertificateAuthorities(raw []byte) ([]bootstrapTrustEntry, error) {
	if len(raw) > MaxBootstrapInputSize {
		return nil, fmt.Errorf("certificate authority input exceeds %d bytes", MaxBootstrapInputSize)
	}
	return parseCertificateAuthorities(raw)
}

func parseExistingCertificateAuthorities(raw []byte) ([]bootstrapTrustEntry, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	return parseCertificateAuthorities(raw)
}

func parseCertificateAuthorities(raw []byte) ([]bootstrapTrustEntry, error) {
	var result []bootstrapTrustEntry
	err := PublicKeys(raw).ForEach(func(_ int, key ssh.PublicKey, comment string) (bool, error) {
		line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(key))
		if comment != "" {
			line = append(append(line, ' '), comment...)
		}
		result = append(result, bootstrapTrustEntry{
			key: key, line: append(line, '\n'), identities: []string{bootstrapPublicKeyIdentity(key)},
		})
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("illegal certificate authority input: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("certificate authority input contains no public key")
	}
	return result, nil
}

func parseImportedKnownHosts(raw []byte) ([]bootstrapTrustEntry, error) {
	if len(raw) > MaxBootstrapInputSize {
		return nil, fmt.Errorf("known hosts input exceeds %d bytes", MaxBootstrapInputSize)
	}
	entries, err := parseKnownHostEntries(raw, true)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("known hosts input contains no host key")
	}
	return entries, nil
}

func parseExistingKnownHosts(raw []byte) ([]bootstrapTrustEntry, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	if err := validateKnownHosts(raw); err != nil {
		return nil, err
	}
	return parseKnownHostEntries(raw, false)
}

func parseKnownHostEntries(raw []byte, rejectMarkers bool) ([]bootstrapTrustEntry, error) {
	var result []bootstrapTrustEntry
	remaining := raw
	for len(bytes.TrimSpace(remaining)) > 0 {
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(remaining)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("illegal known hosts input: %w", err)
		}
		if rejectMarkers && marker != "" {
			return nil, fmt.Errorf("known hosts marker @%s is not accepted", marker)
		}
		if _, certificate := key.(*ssh.Certificate); rejectMarkers && certificate {
			return nil, fmt.Errorf("SSH certificates are not accepted as host keys")
		}
		if key != nil {
			line := knownhosts.Line(hosts, key)
			if marker != "" {
				line = "@" + marker + " " + line
			}
			identities := make([]string, len(hosts))
			for i, host := range hosts {
				identities[i] = marker + "\x00" + knownhosts.Normalize(host) + "\x00" + bootstrapPublicKeyIdentity(key)
			}
			result = append(result, bootstrapTrustEntry{key: key, line: []byte(line + "\n"), identities: identities})
		}
		if len(rest) >= len(remaining) {
			return nil, fmt.Errorf("illegal known hosts input: parser made no progress")
		}
		remaining = rest
	}
	return result, nil
}

func validateExpectedFingerprint(value string) error {
	if value == "" {
		return nil
	}
	const prefix = "SHA256:"
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if !strings.HasPrefix(value, prefix) || err != nil || len(raw) != 32 {
		return fmt.Errorf("illegal expected fingerprint %q", value)
	}
	return nil
}

func bootstrapPublicKeyIdentity(key ssh.PublicKey) string {
	return key.Type() + "\x00" + string(key.Marshal())
}

func WriteBootstrapFile(path string, data []byte, force bool) (rErr error) {
	if path == "" {
		return fmt.Errorf("output path is empty")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("cannot create parent directory for %q: %w", path, err)
	}
	temporary, err := createProtectedTempFile(parent, ".bifroest-bootstrap-*", 0600)
	if err != nil {
		return fmt.Errorf("cannot create temporary file for %q: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			if err := temporary.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
		_ = os.Remove(temporaryPath)
	}()
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("cannot write temporary file for %q: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("cannot flush temporary file for %q: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("cannot close temporary file for %q: %w", path, err)
	}
	temporary = nil
	if err := installBootstrapFile(temporaryPath, path, force); err != nil {
		return fmt.Errorf("cannot install file at %q: %w", path, err)
	}
	return nil
}
