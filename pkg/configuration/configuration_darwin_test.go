package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinDefaultPaths(t *testing.T) {
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/key", DefaultHostKeyLocation)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/client-key", DefaultCertificateIdentityFileLocation)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/ca", DefaultCertificateAuthorityFileLocation)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/auditlog-key", defaultAuditlogIdentityFile)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/auditlog", defaultAuditlogJournalDirectory)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/recordings", defaultAuditlogRecordingDirectory)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/sessions", defaultSessionFsStorage)
	require.Equal(t, `/Library/Application Support/Engity/Bifroest/binaries/{{.version}}/{{.os}}-{{.arch}}-{{.edition}}{{.ext}}`, defaultAlternativesLocation)
	require.Equal(t, "/Library/Application Support/Engity/Bifroest/htpasswd", defaultAuthorizationHtpasswdFile)
}
