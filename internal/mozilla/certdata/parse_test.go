// SPDX-License-Identifier: Apache-2.0

package certdata

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadCertificates(t *testing.T) {
	trustedHash := mozillaTrustIdentifier([]byte{1, 2})
	untrustedHash := mozillaTrustIdentifier([]byte{3})
	actual, err := ReadCertificates(bytes.NewBufferString(fmt.Sprintf(`
# header
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Trusted root"
CKA_VALUE MULTILINE_OCTAL
\001\002
END
CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE

CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Trusted root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
\062\066\060\064\061\065\062\063\065\071\065\071\132
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR

CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Untrusted root"
CKA_VALUE MULTILINE_OCTAL
\003
END
CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE

CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Untrusted root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED
`, encodeTestOctal(trustedHash[:]), encodeTestOctal(untrustedHash[:]))))
	require.NoError(t, err)
	require.Len(t, actual, 2)

	expectedDistrustAfter := time.Date(2026, time.April, 15, 23, 59, 59, 0, time.UTC)
	require.Equal(t, Certificate{
		Label:               "Trusted root",
		DER:                 []byte{1, 2},
		ServerTrust:         TrustTrustedDelegator,
		ServerDistrustAfter: &expectedDistrustAfter,
	}, actual[0])
	require.Equal(t, Certificate{
		Label:       "Untrusted root",
		DER:         []byte{3},
		ServerTrust: TrustNotTrusted,
	}, actual[1])
}

func TestReadCertificatesRejectsTrustForAnotherCertificate(t *testing.T) {
	wrongHash := mozillaTrustIdentifier([]byte{2})
	input := fmt.Sprintf(`
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR`, encodeTestOctal(wrongHash[:]))

	_, err := ReadCertificates(bytes.NewBufferString(input))
	require.ErrorContains(t, err, "has no matching certificate")
}

func TestReadCertificatesAssociatesTrustByHashInsteadOfLabel(t *testing.T) {
	hash := mozillaTrustIdentifier([]byte{1})
	input := fmt.Sprintf(`
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Certificate label"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Trust label"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR`, encodeTestOctal(hash[:]))

	actual, err := ReadCertificates(bytes.NewBufferString(input))
	require.NoError(t, err)
	require.Len(t, actual, 1)
	require.Equal(t, "Certificate label", actual[0].Label)
	require.Equal(t, TrustTrustedDelegator, actual[0].ServerTrust)
}

func TestReadCertificatesAcceptsWhitespaceSeparatedFields(t *testing.T) {
	actual, err := ReadCertificates(bytes.NewBufferString(`
	BEGINDATA
	CKA_CLASS	CK_OBJECT_CLASS	CKO_CERTIFICATE
	CKA_LABEL	UTF8	"Root"
	CKA_VALUE	MULTILINE_OCTAL
\001
END`))

	require.NoError(t, err)
	require.Len(t, actual, 1)
}

func TestReadCertificatesAllowsDuplicateLabelsForDifferentCertificates(t *testing.T) {
	firstHash := mozillaTrustIdentifier([]byte{1})
	secondHash := mozillaTrustIdentifier([]byte{2})
	input := fmt.Sprintf(`
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Shared label"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Shared label"
CKA_VALUE MULTILINE_OCTAL
\002
END
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Shared label"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Shared label"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR`, encodeTestOctal(firstHash[:]), encodeTestOctal(secondHash[:]))

	actual, err := ReadCertificates(bytes.NewBufferString(input))
	require.NoError(t, err)
	require.Len(t, actual, 2)
	require.Equal(t, TrustTrustedDelegator, actual[0].ServerTrust)
	require.Equal(t, TrustTrustedDelegator, actual[1].ServerTrust)
}

func TestReadCertificatesRejectsHashlessNegativeTrustObject(t *testing.T) {
	_, err := ReadCertificates(bytes.NewBufferString(`
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Negative trust"
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END`))

	require.ErrorContains(t, err, "illegal CKA_CERT_SHA1_HASH")
}

func TestReadCertificatesRejectsInvalidInput(t *testing.T) {
	tests := map[string]string{
		"missing header": `CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE`,
		"malformed octal": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
not-octal
END`,
		"unknown trust": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Root"
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_UNKNOWN`,
		"duplicate certificate": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Other root"
CKA_VALUE MULTILINE_OCTAL
\001
END`,
		"conflicting distrust dates": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
\062\066\060\064\061\065\062\063\065\071\065\071\132
END
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "Root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
%s
END
CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
\062\067\060\064\061\065\062\063\065\071\065\071\132
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR`,
		"malformed field line": `
BEGINDATA
CKA_CLASS`,
		"value after multiline marker": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL unexpected`,
		"empty distrust date": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
END`,
		"wrong distrust type": `
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Root"
CKA_VALUE MULTILINE_OCTAL
\001
END
CKA_NSS_SERVER_DISTRUST_AFTER UTF8 "CK_FALSE"`,
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(input, "%s") {
				hash := mozillaTrustIdentifier([]byte{1})
				input = fmt.Sprintf(input, encodeTestOctal(hash[:]))
			}
			_, err := ReadCertificates(bytes.NewBufferString(input))
			if name == "conflicting distrust dates" {
				require.ErrorContains(t, err, "conflicting CKA_NSS_SERVER_DISTRUST_AFTER")
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestParseDistrustAfterUTCTimeCentury(t *testing.T) {
	tests := map[string]int{
		"490101000000Z": 2049,
		"500101000000Z": 1950,
		"680101000000Z": 1968,
		"690101000000Z": 1969,
	}
	for encoded, expectedYear := range tests {
		t.Run(encoded, func(t *testing.T) {
			actual, err := parseDistrustAfter(map[string]value{"distrust": {field: "distrust", type_: "MULTILINE_OCTAL", value: encoded}}, "distrust")
			require.NoError(t, err)
			require.Equal(t, expectedYear, actual.Year())
		})
	}
}

func encodeTestOctal(value []byte) string {
	var result bytes.Buffer
	for _, current := range value {
		fmt.Fprintf(&result, "\\%03o", current)
	}
	return result.String()
}
