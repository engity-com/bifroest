// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- Mozilla NSS uses SHA-1 as the trust-object identifier.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/internal/mozilla/certdata"
)

func TestBuildCaCertsBundleFiltersDistrustedAndSortsNaturally(t *testing.T) {
	evaluatedAt := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	pastDistrust := evaluatedAt.Add(-time.Hour)
	futureDistrust := evaluatedAt.Add(time.Hour)
	source := testCaCertsSource(t,
		testCaCertData{label: "Serial ten", serial: 10, trust: certdata.TrustTrustedDelegator},
		testCaCertData{label: "Serial two", serial: 2, trust: certdata.TrustTrustedDelegator, distrustAfter: &futureDistrust},
		testCaCertData{label: "Distrusted", serial: 1, trust: certdata.TrustTrustedDelegator, distrustAfter: &pastDistrust},
		testCaCertData{label: "Must verify", serial: 3, trust: certdata.TrustMustVerify},
	)

	actual, err := buildCaCertsBundle(context.Background(), source, evaluatedAt)
	require.NoError(t, err)
	require.Equal(t, []string{"2", "10"}, certificateSerials(actual.certificates))
	require.Equal(t, []string{"1"}, certificateSerials(actual.distrusted))
	require.Equal(t, pastDistrust, *actual.distrusted[0].distrustAfter)
	require.Contains(t, actual.sourceStatus[actual.distrusted[0].fingerprint], "server distrust")

	mustVerifyFingerprint := sha256.Sum256(testCaDER(t, 3, "Must verify"))
	require.Equal(t, "Mozilla server trust requires external verification", actual.sourceStatus[mustVerifyFingerprint])
}

func TestLoadSourcePinsResolvedRevision(t *testing.T) {
	expected := testCaCertsSource(t, testCaCertData{label: "Root", serial: 1, trust: certdata.TrustTrustedDelegator})
	revision := strings.Repeat("c", 40)
	committedAt := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/mozilla-firefox/firefox/commits":
			require.Equal(t, caCertsSourceRef, request.URL.Query().Get("sha"))
			require.Equal(t, caCertsSourcePath, request.URL.Query().Get("path"))
			response.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(response, `[{"sha":%q,"commit":{"committer":{"date":%q}}}]`, revision, committedAt.Format(time.RFC3339))
		case "/repos/mozilla-firefox/firefox/contents/" + path.Dir(caCertsSourcePath):
			require.Equal(t, revision, request.URL.Query().Get("ref"))
			response.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(response, `[{"type":"file","name":"certdata.txt","path":%q,"download_url":%q}]`, caCertsSourcePath, server.URL+"/raw/certdata.txt")
		case "/raw/certdata.txt":
			_, _ = response.Write(expected.raw)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	client := github.NewClient(server.Client())
	client.BaseURL = baseURL
	repository := &repo{}
	repository.clientP.Store(client)
	subject := newDependenciesCaCerts(&dependencies{base: &base{repo: repository}})

	actual, err := subject.loadSource(context.Background())

	require.NoError(t, err)
	require.Equal(t, revision, actual.revision)
	require.Equal(t, committedAt, actual.committedAt)
	require.Equal(t, expected.raw, actual.raw)
	require.Equal(t, sha256.Sum256(expected.raw), actual.sha256)
}

func TestBuildCaCertsBundleUsesFingerprintAsSerialTieBreaker(t *testing.T) {
	source := testCaCertsSource(t,
		testCaCertData{label: "First", serial: 1, trust: certdata.TrustTrustedDelegator},
		testCaCertData{label: "Second", serial: 1, trust: certdata.TrustTrustedDelegator},
	)

	actual, err := buildCaCertsBundle(context.Background(), source, time.Now())
	require.NoError(t, err)
	require.Len(t, actual.certificates, 2)
	require.Less(t, bytes.Compare(actual.certificates[0].fingerprint[:], actual.certificates[1].fingerprint[:]), 0)
}

func TestCompareCaCertificates(t *testing.T) {
	retained := testCaCertificate(t, 2, "Retained")
	distrusted := testCaCertificate(t, 1, "Distrusted")
	absent := testCaCertificate(t, 4, "Absent")
	added := testCaCertificate(t, 3, "Added")
	distrustReason := "Mozilla server distrust effective since 2026-09-11T00:00:00Z"

	actual := compareCaCertificates(
		[]caCertificate{absent, retained, distrusted},
		[]caCertificate{added, retained},
		map[[sha256.Size]byte]string{distrusted.fingerprint: distrustReason},
	)

	require.Equal(t, []string{"3"}, certificateSerials(actual.added))
	require.Len(t, actual.removed, 2)
	require.Equal(t, "1", actual.removed[0].certificate.certificate.SerialNumber.String())
	require.Equal(t, distrustReason, actual.removed[0].reason)
	require.Equal(t, "4", actual.removed[1].certificate.certificate.SerialNumber.String())
	require.Equal(t, "not present in the current Mozilla source", actual.removed[1].reason)
}

func TestCompareCaCertificatesUsesFullCertificateIdentity(t *testing.T) {
	existing := testCaCertificate(t, 1, "Original")
	generated := testCaCertificate(t, 1, "Replacement")

	actual := compareCaCertificates([]caCertificate{existing}, []caCertificate{generated}, nil)

	require.Len(t, actual.added, 1)
	require.Equal(t, generated.fingerprint, actual.added[0].fingerprint)
	require.Len(t, actual.removed, 1)
	require.Equal(t, existing.fingerprint, actual.removed[0].certificate.fingerprint)
}

func TestBuildCaCertsBundleRejectsSourceWithoutTrustedServerCertificates(t *testing.T) {
	source := testCaCertsSource(t,
		testCaCertData{label: "Not trusted", serial: 1, trust: certdata.TrustNotTrusted},
	)

	_, err := buildCaCertsBundle(context.Background(), source, time.Now())
	require.ErrorContains(t, err, "contains no trusted server certificates")
}

func TestCaCertsNeedUpdate(t *testing.T) {
	source := testCaCertsSource(t,
		testCaCertData{label: "First", serial: 1, trust: certdata.TrustTrustedDelegator},
		testCaCertData{label: "Second", serial: 2, trust: certdata.TrustTrustedDelegator},
	)
	bundle, err := buildCaCertsBundle(context.Background(), source, time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	var current bytes.Buffer
	require.NoError(t, bundle.writeTo(&current))
	existing, err := parsePemCertificates(current.Bytes())
	require.NoError(t, err)

	require.False(t, caCertsNeedUpdate(current.Bytes(), existing, caCertsDiff{}, bundle))
	require.True(t, caCertsNeedUpdate(nil, existing, caCertsDiff{}, bundle))
	require.True(t, caCertsNeedUpdate(current.Bytes(), existing, caCertsDiff{added: []caCertificate{{}}}, bundle))
	require.True(t, caCertsNeedUpdate(bytes.Replace(current.Bytes(), []byte("## Source SHA-256: "), []byte("## Source SHA-256: 00"), 1), existing, caCertsDiff{}, bundle))
	require.True(t, caCertsNeedUpdate(bytes.Replace(current.Bytes(), []byte("## Policy evaluated at: 2026-07-15T15:49:08Z"), []byte("## Policy evaluated at: 2026-09-11T12:00:00Z"), 1), existing, caCertsDiff{}, bundle))

	header, _, found := bytes.Cut(current.Bytes(), []byte("-----BEGIN CERTIFICATE-----"))
	require.True(t, found)
	reordered := append(append([]byte{}, header...), encodeCaCertificates([]caCertificate{bundle.certificates[1], bundle.certificates[0]})...)
	reorderedCertificates, err := parsePemCertificates(reordered)
	require.NoError(t, err)
	require.True(t, caCertsNeedUpdate(reordered, reorderedCertificates, caCertsDiff{}, bundle))

	newerSource := newCaCertsSource(strings.Repeat("b", 40), source.committedAt.Add(time.Hour), source.raw)
	newerBundle, err := buildCaCertsBundle(context.Background(), newerSource, time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.False(t, caCertsNeedUpdate(current.Bytes(), existing, caCertsDiff{}, newerBundle))
	detailedHeader := bytes.Replace(current.Bytes(), []byte("##\n-----BEGIN CERTIFICATE-----"), []byte("## Included certificates: 2\n##\n-----BEGIN CERTIFICATE-----"), 1)
	require.True(t, caCertsNeedUpdate(detailedHeader, existing, caCertsDiff{}, newerBundle))
}

func TestBuildCaCertsBundleRejectsFutureCommitTime(t *testing.T) {
	source := testCaCertsSource(t, testCaCertData{label: "Root", serial: 1, trust: certdata.TrustTrustedDelegator})

	_, err := buildCaCertsBundle(context.Background(), source, source.committedAt.Add(-time.Second))

	require.ErrorContains(t, err, "is after policy observation time")
}

func TestWriteFileAtomicallyReplacesExistingFile(t *testing.T) {
	target := filepath.Join(t.TempDir(), "ca-certs.crt")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0600))

	require.NoError(t, writeFileAtomically(target, []byte("new"), 0644))

	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), actual)
	info, err := os.Stat(target)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0644), info.Mode().Perm())
	}
}

func TestFutureDistrustChangesEffectiveCertificateSet(t *testing.T) {
	distrustAfter := time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC)
	source := testCaCertsSource(t,
		testCaCertData{label: "Stable", serial: 1, trust: certdata.TrustTrustedDelegator},
		testCaCertData{label: "Scheduled distrust", serial: 2, trust: certdata.TrustTrustedDelegator, distrustAfter: &distrustAfter},
	)

	before, err := buildCaCertsBundle(context.Background(), source, distrustAfter.Add(-time.Second))
	require.NoError(t, err)
	after, err := buildCaCertsBundle(context.Background(), source, distrustAfter)
	require.NoError(t, err)
	diff := compareCaCertificates(before.certificates, after.certificates, after.sourceStatus)

	require.Empty(t, diff.added)
	require.Len(t, diff.removed, 1)
	require.Equal(t, "2", diff.removed[0].certificate.certificate.SerialNumber.String())
	require.Equal(t, distrustAfter, after.evaluatedAt)
}

func TestCaCertsBundleWriteTo(t *testing.T) {
	evaluatedAt := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	distrustAfter := evaluatedAt.Add(-time.Hour)
	source := testCaCertsSource(t,
		testCaCertData{label: "Included", serial: 2, trust: certdata.TrustTrustedDelegator},
		testCaCertData{label: "Distrusted", serial: 1, trust: certdata.TrustTrustedDelegator, distrustAfter: &distrustAfter},
	)
	bundle, err := buildCaCertsBundle(context.Background(), source, evaluatedAt)
	require.NoError(t, err)

	var first bytes.Buffer
	require.NoError(t, bundle.writeTo(&first))
	laterBundle, err := buildCaCertsBundle(context.Background(), source, evaluatedAt.Add(24*time.Hour))
	require.NoError(t, err)
	var second bytes.Buffer
	require.NoError(t, laterBundle.writeTo(&second))
	require.Equal(t, first.Bytes(), second.Bytes())

	output := first.String()
	require.Contains(t, output, caCertsHeaderFormatLine)
	require.Contains(t, output, "## SPDX-License-Identifier: MPL-2.0")
	require.Contains(t, output, "## Source revision: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.Contains(t, output, "## Policy evaluated at: 2026-09-11T11:00:00Z")
	require.NotContains(t, output, "## Included certificates:")
	require.NotContains(t, output, "## Excluded because")
	require.NotContains(t, output, "## Certificate state SHA-256:")
	require.NotContains(t, output, "## Certificate payload SHA-256:")

	parsed, err := parsePemCertificates(first.Bytes())
	require.NoError(t, err)
	require.Equal(t, []string{"2"}, certificateSerials(parsed))
}

func TestParsePemCertificatesRejectsDuplicateCertificate(t *testing.T) {
	certificate := testCaCertificate(t, 1, "Duplicate")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.certificate.Raw})

	_, err := parsePemCertificates(append(encoded, encoded...))
	require.ErrorContains(t, err, "duplicate certificate")
}

type testCaCertData struct {
	label         string
	serial        int64
	trust         certdata.Trust
	distrustAfter *time.Time
}

func testCaCertsSource(t *testing.T, certificates ...testCaCertData) *caCertsSource {
	t.Helper()
	var raw strings.Builder
	raw.WriteString("# License, v. 2.0: http://mozilla.org/MPL/2.0/\nBEGINDATA\n")
	derByLabel := make(map[string][]byte, len(certificates))
	for _, certificate := range certificates {
		der := testCaDER(t, certificate.serial, certificate.label)
		derByLabel[certificate.label] = der
		fmt.Fprintf(&raw, "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_LABEL UTF8 %s\nCKA_VALUE MULTILINE_OCTAL\n%s\nEND\n",
			strconv.Quote(certificate.label), encodeOctal(der))
		if certificate.distrustAfter == nil {
			raw.WriteString("CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE\n")
		} else {
			fmt.Fprintf(&raw, "CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL\n%s\nEND\n",
				encodeOctal([]byte(certificate.distrustAfter.UTC().Format("060102150405Z"))))
		}
	}
	for _, certificate := range certificates {
		identifier := sha1.Sum(derByLabel[certificate.label]) //nolint:gosec // This models Mozilla's trust-object identifier.
		fmt.Fprintf(&raw, "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\nCKA_LABEL UTF8 %s\nCKA_CERT_SHA1_HASH MULTILINE_OCTAL\n%s\nEND\nCKA_TRUST_SERVER_AUTH CK_TRUST %s\n",
			strconv.Quote(certificate.label), encodeOctal(identifier[:]), certificate.trust)
	}
	return newCaCertsSource(strings.Repeat("a", 40), time.Date(2026, time.July, 15, 15, 49, 8, 0, time.UTC), []byte(raw.String()))
}

func testCaCertificate(t *testing.T, serial int64, label string) caCertificate {
	t.Helper()
	result, err := newCaCertificate(label, testCaDER(t, serial, label))
	require.NoError(t, err)
	return result
}

func testCaDER(t *testing.T, serial int64, commonName string) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte(commonName))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(nil, template, template, privateKey.Public(), privateKey)
	require.NoError(t, err)
	return der
}

func encodeOctal(value []byte) string {
	var result strings.Builder
	for _, current := range value {
		fmt.Fprintf(&result, "\\%03o", current)
	}
	return result.String()
}

func certificateSerials(certificates []caCertificate) []string {
	result := make([]string, len(certificates))
	for i, certificate := range certificates {
		result[i] = certificate.certificate.SerialNumber.String()
	}
	return result
}
